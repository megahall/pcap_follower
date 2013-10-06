#ifndef __BRANCH_PREDICTION_H__
#define __BRANCH_PREDICTION_H__

#ifdef __GNUC__
#    define likely(x)       __builtin_expect(!!(x), 1)
#    define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#    define likely(x)       (x)
#    define unlikely(x)     (x)
#endif

#endif // __BRANCH_PREDICTION_H__
