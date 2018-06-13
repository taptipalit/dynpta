/* LINTLIBRARY */
#include "llvm/Analysis/SVF/CUDD/util.h"

/* backwards compatibility */
long 
ptime()
{
    return util_cpu_time();
}
