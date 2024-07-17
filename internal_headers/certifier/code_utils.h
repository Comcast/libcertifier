#ifndef CODE_UTILS_H
#define CODE_UTILS_H

#define ReturnErrorOnFailure(expr)                                                                                                 \
    do                                                                                                                             \
    {                                                                                                                              \
        int __err = (expr);                                                                                                        \
        if (__err != 0)                                                                                                            \
        {                                                                                                                          \
            return __err;                                                                                                          \
        }                                                                                                                          \
    } while (0)

#define VerifyOrReturnError(expr, code)                                                                                            \
    do                                                                                                                             \
    {                                                                                                                              \
        if (!(expr))                                                                                                               \
        {                                                                                                                          \
            return (code);                                                                                                         \
        }                                                                                                                          \
    } while (0)

#define VerifyOrExit(statement, action)                                                                                            \
    do                                                                                                                             \
    {                                                                                                                              \
        if ((statement) != 1)                                                                                                      \
        {                                                                                                                          \
            action;                                                                                                                \
            goto exit;                                                                                                             \
        }                                                                                                                          \
    } while (0)

#endif // CODE_UTILS_H
