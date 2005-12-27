#ifndef _PAM_TCB_SUPPORT_H
#define _PAM_TCB_SUPPORT_H

#include <pwd.h>
#include <shadow.h>

#define PASSWD_FILE			"/etc/passwd"
#define SHADOW_FILE			"/etc/shadow"

/* should be large enough to hold "*NP*" */
#define HASH_PREFIX_SIZE		5

/* Password prompt to use for authentication */
#define PROMPT_PASS \
	"Password: "

/* Prompts to use for password changes */
#define PROMPT_OLDPASS \
	"Enter current password: "
#define PROMPT_NEWPASS1 \
	"Enter new password: "
#define PROMPT_NEWPASS2 \
	"Re-type new password: "

/* Possible messages during account management */
#define MESSAGE_ACCT_EXPIRED \
	"Your account has expired; please contact your system administrator."
#define MESSAGE_PASS_EXPIRED \
	"You are required to change your password immediately."
#define MESSAGE_WARN_EXPIRE \
	"Warning: your password will expire in %d day%s."

/* Possible messages during password changes */
#define MESSAGE_CHANGING \
	"Changing password for %s."
#define MESSAGE_PASS_SAME \
	"Password unchanged."
#define MESSAGE_PASS_NONE \
	"No password supplied."
#define MESSAGE_TOOSOON \
	"You must wait longer to change your password."
#define MESSAGE_MISTYPED \
	"Sorry, passwords do not match."

/*
 * Here are the various boolean options recognized by the unix module.
 * They are enumerated here and then defined below. Internal arguments
 * are given NULL tokens.
 */
enum {
	UNIX__OLD_PASSWD = 0,	/* internal */
	UNIX__VERIFY_PASSWD,	/* internal */
	UNIX__IAMROOT,		/* internal */

	UNIX_AUDIT,		/* print more things than debug, */
				/* some information may be sensitive */
	UNIX_NOT_SET_PASS,	/* don't set the AUTHTOK items */

	UNIX__PRELIM,		/* internal */
	UNIX__UPDATE,		/* internal */
	UNIX__QUIET,		/* internal */
	UNIX_USE_AUTHTOK,	/* insist on reading PAM_AUTHTOK */

	UNIX_SHADOW,		/* use shadow for auth */
	UNIX_NISPLUS,		/* wish to use NIS+ for auth */
	UNIX_PASSWD,		/* retr hashes from /etc/passwd for auth */

	UNIX_OPENLOG,		/* use openlog(3)/closelog(3) calls */
	UNIX__NULLOK,		/* null token ok */
	UNIX_DEBUG,		/* send more info to syslog(3) */
	UNIX_NODELAY,		/* admin does not want a fail-delay */
	UNIX_MD5_PASS,		/* force the use of MD5-based hashes */
	UNIX_PLAIN_CRYPT,	/* use crypt(3) instead of crypt_ra(3) */
	UNIX_FORKAUTH,		/* fork for authentication */
	UNIX_LIKE_AUTH,		/* use auth's return value with setcred */
	UNIX_NOLOG,		/* supress logging */
	UNIX_NOLOG_BLANK,	/* don't log failed blank password tests */

	_UNIX_BOOLS		/* number of ctrl arguments defined */
};

#define _INT_BITS \
	(sizeof(int) * 8)
#define OPT_SIZE \
	((_UNIX_BOOLS - 1) / _INT_BITS + 1)

enum {
	USE_NONE = 0,		/* ask for password via the conv function */
	USE_TRY,		/* try to get password(s) from PAM_*AUTHTOK */
	USE_FORCED		/* get password(s) from PAM_*AUTHTOK or fail */
};

enum {
	WRITE_PASSWD = 0,	/* write changed password to /etc/passwd */
	WRITE_SHADOW,		/* write changed password to /etc/shadow */
	WRITE_NIS,		/* write changed password via NIS */
	WRITE_TCB		/* write changed password to /etc/tcb/ */
};

struct cmdline_opts {
	char *optname;
	const char *value, *orig;
};

struct pam_unix_params {
	unsigned int ctrl[OPT_SIZE];
	int authtok_usage;
	int write_to;
	const unsigned char *crypt_prefix;
	const unsigned char *helper;
	unsigned long count;
};
extern struct pam_unix_params pam_unix_param;

/*
 * macro to determine if a given flag is on
 */
#define flg(x) \
	(1U << (x))
#define on(x) \
	(flg((x) % _INT_BITS) & pam_unix_param.ctrl[(x) / _INT_BITS])

/*
 * macro to determine that a given flag is NOT on
 */
#define off(x) \
	(!on(x))

/*
 * macro to turn on/off a ctrl flag manually
 */
#define set(x) \
	pam_unix_param.ctrl[(x) / _INT_BITS] |= flg((x) % _INT_BITS)
#define unset(x) \
	pam_unix_param.ctrl[(x) / _INT_BITS] &= ~flg((x) % _INT_BITS)

struct unix_verify_password_param {
	pam_handle_t *pamh;
	const char *user;
	const char *pass;
};

/* use this to free strings, ESPECIALLY password strings */
#define _pam_delete(xx) \
{ \
	_pam_overwrite(xx); \
	_pam_drop(xx); \
}

#if defined(__LIBPAM_VERSION) || defined(__LINUX_PAM__) || defined(_OPENPAM)
typedef const void *pam_item_t;
#else
typedef void *pam_item_t;
#endif

#if defined(__LIBPAM_VERSION) || defined(__LINUX_PAM__)
typedef const void *pam_data_t;
#else
typedef void *pam_data_t;
#endif

extern int _unix_user_in_db(const char *, char *);

typedef int (*cb_func) (const void *);
extern int _unix_fork(cb_func, const void *);

extern void _log_err(int err, const char *format, ...)
#if defined(__GNUC__) && __GNUC__ >= 2 && (__GNUC__ > 2 || __GNUC_MINOR__ >= 5) && !__STRICT_ANSI__
	__attribute__ ((format(printf, 2, 3)));
#else
	;
#endif

extern int _make_remark(pam_handle_t * pamh, int type, const char *text);
extern int _set_ctrl(int flags, int argc, const char **argv);
extern int _unix_comesfromsource(const char *user, int files, int nis);
extern int _unix_blankpasswd(const char *user);
extern int _unix_verify_password(pam_handle_t *, const char *, const char *);
extern int _unix_read_password(pam_handle_t *pamh, const char *comment,
    const char *prompt1, const char *prompt2, const char *data_name,
    const char **pass);
extern int unix_getspnam(struct spwd **, const struct passwd *);
extern char *crypt_wrapper(const char *, const char *);
extern char *do_crypt(const char *);

#endif
