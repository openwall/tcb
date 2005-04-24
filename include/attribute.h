#ifndef TCB_ATTRIBUTE_H_
#define TCB_ATTRIBUTE_H_

#ifndef unused
# if !defined(__GNUC__) || __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 7) || __STRICT_ANSI__
#  define unused
# else
#  define unused __attribute__((unused))
# endif
#endif

#endif /* TCB_ATTRIBUTE_H_ */
