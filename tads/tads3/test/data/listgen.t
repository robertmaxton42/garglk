#include <tads.h>

main(args)
{
    sayList('10 even integers', List.generate({i: i*2}, 10));

    local a = 0, b = 1;
    sayList('20 Fibonacci numbers', List.generate(new function() {
        local cur = a;
        return a = b, b = cur + a, cur;
    }, 20));

    a = 0, b = 1;
    sayList('30 Fibonacci numbers', List.generate(
        {: local f = a, a = b, b = f + a, f }, 30));

    a = b = 1;
    local c = 1;
    sayList('25 Padovan numbers', List.generate(
        {: local ret = a, a = b, b = c, c = ret + a, ret}, 25));
}

sayList(desc, lst)
{
    if (desc != nil)
        "<<desc>>: ";

    "[";
    for (local i = 1, local len = lst.length() ; i <= len ; ++i)
    {
        if (i > 1)
            ", ";
        
        local ele = lst[i];
        switch (dataType(ele))
        {
        default:
            "<<ele>>";
            break;
            
        case TypeList:
            sayList(nil, ele);
            break;
        }
    }
    "]\b";
}

