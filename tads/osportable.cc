/* Adapted from src/osportable.cc from FrobTADS 1.2.3.
 * FrobTADS copyright (C) 2009 Nikos Chantziaras.
 */

/* This file implements some of the functions described in
 * tads2/osifc.h.  We don't need to implement them all, as most of them
 * are provided by tads2/osnoui.c and tads2/osgen3.c.
 *
 * This file implements the "portable" subset of these functions;
 * functions that depend upon curses/ncurses are defined in oscurses.cc.
 */
#include "os.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <time.h>
#include <dirent.h>

#define HAVE_MKDIR 1

/* Safe strcpy.
 * (Copied from tads2/msdos/osdos.c)
 */
static void
safe_strcpy(char *dst, size_t dstlen, const char *src)
{
    size_t copylen;

    /* do nothing if there's no output buffer */
    if (dst == 0 || dstlen == 0)
        return;

    /* do nothing if the source and destination buffers are the same */
    if (dst == src)
        return;

    /* use an empty string if given a null string */
    if (src == 0)
        src = "";

    /* 
     *   figure the copy length - use the smaller of the actual string size
     *   or the available buffer size, minus one for the null terminator 
     */
    copylen = strlen(src);
    if (copylen > dstlen - 1)
        copylen = dstlen - 1;

    /* copy the string (or as much as we can) */
    memcpy(dst, src, copylen);

    /* null-terminate it */
    dst[copylen] = '\0';
}

/* Duplicate a file hand.e
 */
osfildef*
osfdup(osfildef *orig, const char *mode)
{
    char realmode[5];
    char *p = realmode;
    const char *m;

    /* verify that there aren't any unrecognized mode flags */
    for (m = mode ; *m != '\0' ; ++m)
    {
        if (strchr("rw+bst", *m) == 0)
            return 0;
    }

    /* figure the read/write mode - translate r+ and w+ to r+ */
    if ((mode[0] == 'r' || mode[0] == 'w') && mode[1] == '+')
        *p++ = 'r', *p++ = '+';
    else if (mode[0] == 'r')
        *p++ = 'r';
    else if (mode[0] == 'w')
        *p++ = 'w';
    else
        return 0;

    /* end the mode string */
    *p = '\0';

    /* duplicate the handle in the given mode */
    return fdopen(dup(fileno(orig)), mode);
}

/* Create a directory.
 */
int
os_mkdir( const char* dir, int create_parents )
{
    //assert(dir != 0);

    if (dir[0] == '\0')
        return true;

    // Copy the directory name to a new string so we can strip any trailing
    // path seperators.
    size_t len = strlen(dir);
    char* tmp = new char[len + 1];
    strncpy(tmp, dir, len);
    while (tmp[len - 1] == OSPATHCHAR)
        --len;
    tmp[len] = '\0';

    // If we're creating intermediate diretories, and the path contains
    // multiple elements, recursively create the parent directories first.
    if (create_parents and strchr(tmp, OSPATHCHAR) != 0) {
        char par[OSFNMAX];

        // Extract the parent path.
        os_get_path_name(par, sizeof(par), tmp);

        // If the parent doesn't already exist, create it recursively.
        if (osfacc(par) != 0 and not os_mkdir(par, true)) {
            delete[] tmp;
            return false;
        }
    }

    // Create the directory.
    int ret =
#if HAVE_MKDIR
#   if MKDIR_TAKES_ONE_ARG
             mkdir(tmp);
#   else
             mkdir(tmp, S_IRWXU | S_IRWXG | S_IRWXO);
#   endif
#elif HAVE__MKDIR
             _mkdir(tmp);
#else
#   error "Neither mkdir() nor _mkdir() is available on this system."
#endif
    delete[] tmp;
    return ret == 0;
}

/* Remove a directory.
 */
int
os_rmdir( const char *dir )
{
    return rmdir(dir) == 0;
}

/* Get a file's mode/type.  This returns the same information as
 * the 'mode' member of os_file_stat_t from os_file_stat(), so we
 * simply call that routine and return the value.
 */
int
osfmode( const char *fname, int follow_links, unsigned long *mode,
         unsigned long* attr )
{
    os_file_stat_t s;
    int ok;
    if ((ok = os_file_stat(fname, follow_links, &s)) != false) {
        if (mode != NULL)
            *mode = s.mode;
        if (attr != NULL)
            *attr = s.attrs;
    }
    return ok;
}

/* Get full stat() information on a file.
 *
 * TODO: Windows implementation for mingw.
 */
int
os_file_stat( const char *fname, int follow_links, os_file_stat_t *s )
{
    struct stat buf;
    if ((follow_links ? stat(fname, &buf) : lstat(fname, &buf)) != 0)
        return false;

    s->sizelo = (uint32_t)(buf.st_size & 0xFFFFFFFF);
    s->sizehi = sizeof(buf.st_size) > 4
                ? (uint32_t)((buf.st_size >> 32) & 0xFFFFFFFF)
                : 0;
    s->cre_time = buf.st_ctime;
    s->mod_time = buf.st_mtime;
    s->acc_time = buf.st_atime;
    s->mode = buf.st_mode;
    s->attrs = 0;

    if (os_get_root_name(fname)[0] == '.') {
        s->attrs |= OSFATTR_HIDDEN;
    }

    // If we're the owner, check if we have read/write access.
    if (geteuid() == buf.st_uid) {
        if (buf.st_mode & S_IRUSR)
            s->attrs |= OSFATTR_READ;
        if (buf.st_mode & S_IWUSR)
            s->attrs |= OSFATTR_WRITE;
        return true;
    }

    // Check if one of our groups matches the file's group and if so, check
    // for read/write access.

    // Also reserve a spot for the effective group ID, which might
    // not be included in the list in our next call.
    int grpSize = getgroups(0, NULL) + 1;
    // Paranoia.
    if (grpSize > NGROUPS_MAX or grpSize < 0)
        return false;
    gid_t* groups = new gid_t[grpSize];
    if (getgroups(grpSize - 1, groups + 1) < 0) {
        delete[] groups;
        return false;
    }
    groups[0] = getegid();
    int i;
    for (i = 0; i < grpSize and buf.st_gid != groups[i]; ++i)
        ;
    delete[] groups;
    if (i < grpSize) {
        if (buf.st_mode & S_IRGRP)
            s->attrs |= OSFATTR_READ;
        if (buf.st_mode & S_IWGRP)
            s->attrs |= OSFATTR_WRITE;
        return true;
    }

    // We're neither the owner of the file nor do we belong to its
    // group.  Check whether the file is world readable/writable.
    if (buf.st_mode & S_IROTH)
        s->attrs |= OSFATTR_READ;
    if (buf.st_mode & S_IWOTH)
        s->attrs |= OSFATTR_WRITE;
    return true;
}

/* Manually resolve a symbolic link.
 */
int
os_resolve_symlink( const char *fname, char *target, size_t target_size )
{
    // get the stat() information for the *undereferenced* link; if
    // it's not actually a link, there's nothing to resolve
    struct stat buf;
    if (lstat(fname, &buf) != 0 or (buf.st_mode & S_IFLNK) == 0)
        return false;

    // read the link contents (maxing out at the buffer size)
    size_t copylen = (size_t)buf.st_size;
    if (copylen > target_size - 1)
        copylen = target_size - 1;
    if (readlink(fname, target, copylen) < 0)
        return false;

    // null-terminate the result and return success
    target[copylen] = '\0';
    return true;
}

/* Get the time since the Unix Epoch in seconds and nanoseconds.
 */
void
os_time_ns( os_time_t *seconds, long *nanoseconds )
{
    // Get the current time.
    static const clockid_t clockType = CLOCK_REALTIME;
    struct timespec currTime;
    clock_gettime(clockType, &currTime);

    // return the data
    *seconds = currTime.tv_sec;
    *nanoseconds = currTime.tv_nsec;
}

/* Open a directory search.
 */
int os_open_dir(const char *dirname, osdirhdl_t *hdl)
{
    return (*hdl = opendir(dirname)) != NULL;
}

/* Read the next result in a directory search.
 */
int os_read_dir(osdirhdl_t hdl, char *buf, size_t buflen)
{
    // Read the next directory entry - if we've exhausted the search,
    // return failure.
    struct dirent *d = readdir(hdl);
    if (d == 0)
        return false;

    // return this entry
    safe_strcpy(buf, buflen, d->d_name);
    return true;
}

/* Close a directory search.
 */
void os_close_dir(osdirhdl_t hdl)
{
    closedir(hdl);
}


/* Determine if the given filename refers to a special file.
 *
 * tads2/osnoui.c defines its own version when MSDOS is defined.
 */
#ifndef MSDOS
os_specfile_t
os_is_special_file( const char* fname )
{
    // We also check for "./" and "../" instead of just "." and
    // "..".  (We use OSPATHCHAR instead of '/' though.)
    const char selfWithSep[3] = {'.', OSPATHCHAR, '\0'};
    const char parentWithSep[4] = {'.', '.', OSPATHCHAR, '\0'};
    if ((strcmp(fname, ".") == 0) or (strcmp(fname, selfWithSep) == 0)) return OS_SPECFILE_SELF;
    if ((strcmp(fname, "..") == 0) or (strcmp(fname, parentWithSep) == 0)) return OS_SPECFILE_PARENT;
    return OS_SPECFILE_NONE;
}
#endif

extern "C" void canonicalize_path(char *path);

/* Resolve symbolic links in a path.  It's okay for 'buf' and 'path'
 * to point to the same buffer if you wish to resolve a path in place.
 */
static void
resolve_path( char *buf, size_t buflen, const char *path )
{
    // Starting with the full path string, try resolving the path with
    // realpath().  The tricky bit is that realpath() will fail if any
    // component of the path doesn't exist, but we need to resolve paths
    // for prospective filenames, such as files or directories we're
    // about to create.  So if realpath() fails, remove the last path
    // component and try again with the remainder.  Repeat until we
    // can resolve a real path, or run out of components to remove.
    // The point of this algorithm is that it will resolve as much of
    // the path as actually exists in the file system, ensuring that
    // we resolve any links that affect the path.  Any portion of the
    // path that doesn't exist obviously can't refer to a link, so it
    // will be taken literally.  Once we've resolved the longest prefix,
    // tack the stripped portion back on to form the fully resolved
    // path.

    // make a writable copy of the path to work with
    size_t pathl = strlen(path);
    char *mypath = new char[pathl + 1];
    memcpy(mypath, path, pathl + 1);

    // start at the very end of the path, with no stripped suffix yet
    char *suffix = mypath + pathl;
    char sl = '\0';

    // keep going until we resolve something or run out of path
    for (;;)
    {
        // resolve the current prefix, allocating the result
        char *rpath = realpath(mypath, 0);

        // un-split the path
        *suffix = sl;

        // if we resolved the prefix, return the result
        if (rpath != 0)
        {
            // success - if we separated a suffix, reattach it
            if (*suffix != '\0')
            {
                // reattach the suffix (the part after the '/')
                for ( ; *suffix == '/' ; ++suffix) ;
                os_build_full_path(buf, buflen, rpath, suffix);
            }
            else
            {
                // no suffix, so we resolved the entire path
                safe_strcpy(buf, buflen, rpath);
            }

            // done with the resolved path
            free(rpath);

            // ...and done searching
            break;
        }

        // no luck with realpath(); search for the '/' at the end of the
        // previous component in the path 
        for ( ; suffix > mypath && *(suffix-1) != '/' ; --suffix) ;

        // skip any redundant slashes
        for ( ; suffix > mypath && *(suffix-1) == '/' ; --suffix) ;

        // if we're at the root element, we're out of path elements
        if (suffix == mypath)
        {
            // we can't resolve any part of the path, so just return the
            // original path unchanged
            safe_strcpy(buf, buflen, mypath);
            break;
        }

        // split the path here into prefix and suffix, and try again
        sl = *suffix;
        *suffix = '\0';
    }

    // done with our writable copy of the path
    delete [] mypath;
}

/* Is the given file in the given directory?
 */
int
os_is_file_in_dir( const char* filename, const char* path,
                   int allow_subdirs, int match_self )
{
    char filename_buf[OSFNMAX], path_buf[OSFNMAX];
    size_t flen, plen;

    // Absolute-ize the filename, if necessary.
    if (not os_is_file_absolute(filename)) {
        os_get_abs_filename(filename_buf, sizeof(filename_buf), filename);
        filename = filename_buf;
    }

    // Absolute-ize the path, if necessary.
    if (not os_is_file_absolute(path)) {
        os_get_abs_filename(path_buf, sizeof(path_buf), path);
        path = path_buf;
    }

    // Canonicalize the paths, to remove .. and . elements - this will make
    // it possible to directly compare the path strings.  Also resolve it
    // to the extent possible, to make sure we're not fooled by symbolic
    // links.
    safe_strcpy(filename_buf, sizeof(filename_buf), filename);
    canonicalize_path(filename_buf);
    resolve_path(filename_buf, sizeof(filename_buf), filename_buf);
    filename = filename_buf;

    safe_strcpy(path_buf, sizeof(path_buf), path);
    canonicalize_path(path_buf);
    resolve_path(path_buf, sizeof(path_buf), path_buf);
    path = path_buf;

    // Get the length of the filename and the length of the path.
    flen = strlen(filename);
    plen = strlen(path);

    // If the path ends in a separator character, ignore that.
    if (plen > 0 and path[plen-1] == '/')
        --plen;

    // if the names match, return true if and only if we're matching the
    // directory to itself
    if (plen == flen && memcmp(filename, path, flen) == 0)
        return match_self;

    // Check that the filename has 'path' as its path prefix.  First, check
    // that the leading substring of the filename matches 'path', ignoring
    // case.  Note that we need the filename to be at least two characters
    // longer than the path: it must have a path separator after the path
    // name, and at least one character for a filename past that.
    if (flen < plen + 2 or memcmp(filename, path, plen) != 0)
        return false;

    // Okay, 'path' is the leading substring of 'filename'; next make sure
    // that this prefix actually ends at a path separator character in the
    // filename.  (This is necessary so that we don't confuse "c:\a\b.txt"
    // as matching "c:\abc\d.txt" - if we only matched the "c:\a" prefix,
    // we'd miss the fact that the file is actually in directory "c:\abc",
    // not "c:\a".)
    if (filename[plen] != '/')
        return false;

    // We're good on the path prefix - we definitely have a file that's
    // within the 'path' directory or one of its subdirectories.  If we're
    // allowed to match on subdirectories, we already have our answer
    // (true).  If we're not allowed to match subdirectories, we still have
    // one more check, which is that the rest of the filename is free of
    // path separator charactres.  If it is, we have a file that's directly
    // in the 'path' directory; otherwise it's in a subdirectory of 'path'
    // and thus isn't a match.
    if (allow_subdirs) {
        // Filename is in the 'path' directory or one of its
        // subdirectories, and we're allowed to match on subdirectories, so
        // we have a match.
        return true;
    }

    // We're not allowed to match subdirectories, so scan the rest of
    // the filename for path separators.  If we find any, the file is
    // in a subdirectory of 'path' rather than directly in 'path'
    // itself, so it's not a match.  If we don't find any separators,
    // we have a file directly in 'path', so it's a match.
    const char* p;
    for (p = filename; *p != '\0' and *p != '/' ; ++p)
        ;

    // If we reached the end of the string without finding a path
    // separator character, it's a match .
    return *p == '\0';
}

/* ------------------------------------------------------------------------ */
/*
 * Get the file system roots.  Unix has the lovely unified namespace with
 * just the one root, /, so this is quite simple.
 */
size_t os_get_root_dirs(char *buf, size_t buflen)
{
    static const char ret[] = { '/', 0, 0 };
    
    // if there's room, copy the root string "/" and an extra null
    // terminator for the overall list
    if (buflen >= sizeof(ret))
        memcpy(buf, ret, sizeof(ret));

    // return the required size
    return sizeof(ret);
}
