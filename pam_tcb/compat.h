#ifndef _PAM_TCB_COMPAT_H
#define _PAM_TCB_COMPAT_H

extern void TCB_FORMAT((printf, 3, 4)) TCB_NONNULL((3))
pam_syslog(pam_handle_t *, int, const char *, ...);

#ifndef _OPENPAM
extern int TCB_FORMAT((printf, 4, 5)) TCB_NONNULL((1,4))
pam_prompt(pam_handle_t *pamh, int style, char **response,
    const char *fmt, ...);
#define pam_error(pamh, fmt...) pam_prompt(pamh, PAM_ERROR_MSG, NULL, fmt)
#define pam_info(pamh, fmt...) pam_prompt(pamh, PAM_TEXT_INFO, NULL, fmt)
#endif /* !_OPENPAM */

#endif
