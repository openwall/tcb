#ifndef TCB_ATTRIBUTE_H_
#define TCB_ATTRIBUTE_H_

#if defined(__GNUC__) && defined(__GNUC_MINOR__) && !defined(__STRICT_ANSI__)
# define TCB_GNUC_PREREQ(maj, min) \
        ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
# define TCB_GNUC_PREREQ(maj, min) 0
#endif

#if TCB_GNUC_PREREQ(2,5)
# define TCB_FORMAT(params) __attribute__((__format__ params))
#else
# define TCB_FORMAT(params)
#endif

#if TCB_GNUC_PREREQ(2,7)
# define unused __attribute__((unused))
#else
# define unused
#endif

#if TCB_GNUC_PREREQ(3,3)
# define TCB_NONNULL(params) __attribute__((__nonnull__ params))
#else
# define TCB_NONNULL(params)
#endif

#endif /* TCB_ATTRIBUTE_H_ */
