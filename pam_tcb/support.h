#ifndef _PAM_TCB_SUPPORT_H
#define _PAM_TCB_SUPPORT_H

#include <pwd.h>
#include <shadow.h>

#include "attribute.h"

#ifdef __LINUX_PAM__
# include <security/pam_ext.h>
#else
# include "compat.h"
#endif

#if defined(ENABLE_NLS) && defined(NLS_PACKAGE)
#include <libintl.h>
#define _(msgid) dgettext(NLS_PACKAGE, msgid)
#define P3_(msgid, msgid_plural, count) \
	(dngettext(NLS_PACKAGE, (msgid), (msgid_plural), (count)))
#define N_(msgid) msgid
#else
#define _(msgid) (msgid)
#define P3_(msgid, msgid_plural, count) \
	((count) == 1 ? (msgid) : (msgid_plural))
#define N_(msgid) msgid
#endif /* ENABLE_NLS && NLS_PACKAGE */

#define PASSWD_FILE			"/etc/passwd"
#define SHADOW_FILE			"/etc/shadow"

/* should be large enough to hold "*NP*" */
#define HASH_PREFIX_SIZE		5

/* Possible messages during account management */
#define MESSAGE_ACCT_EXPIRED \
	_("Your account has expired; please contact your system administrator.")
#define MESSAGE_PASS_ENFORCED \
	_("You are required to change your password immediately (administrator enforced).")
#define MESSAGE_PASS_EXPIRED \
	_("You are required to change your password immediately (password expired).")
#define MESSAGE_WARN_EXPIRE(count) \
	P3_("Warning: your password will expire in %d day.", \
	    "Warning: your password will expire in %d days.", \
	    (count)), (count)


/* Possible messages during password changes */
#define MESSAGE_CHANGING \
	_("Changing password for %s.")
#define MESSAGE_PASS_SAME \
	_("The password has not been changed.")
#define MESSAGE_PASS_NONE \
	_("No password has been supplied.")
#define MESSAGE_TOOSOON \
	_("You must wait longer to change your password.")

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
	UNIX_USE_FIRST_PASS,	/* don't prompt the user for passwords */
	UNIX_TRY_FIRST_PASS,	/* take passwords from PAM_AUTHTOK and possibly
				   PAM_OLDAUTHTOK items, but prompt the user
				   if the appropriate PAM item is unset */
	UNIX_AUTHTOK_TYPE,	/* the type of password to use in prompts */

	UNIX__PRELIM,		/* internal */
	UNIX__UPDATE,		/* internal */
	UNIX__QUIET,		/* internal */
	UNIX_USE_AUTHTOK,	/* insist on reading PAM_AUTHTOK */

	UNIX_SHADOW,		/* use shadow for auth */
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
	WRITE_PASSWD = 0,	/* write changed password to /etc/passwd */
	WRITE_SHADOW,		/* write changed password to /etc/shadow */
	WRITE_TCB		/* write changed password to /etc/tcb/ */
};

struct cmdline_opts {
	const char *optname;
	const char *value, *orig;
};

struct pam_unix_params {
	unsigned int ctrl[OPT_SIZE];
	int write_to;
	const char *crypt_prefix;
	const char *helper;
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

extern int _unix_user_in_db(pam_handle_t *, const char *, char *);

typedef int (*cb_func) (pam_handle_t *, const void *);
extern int _unix_fork(pam_handle_t *, cb_func, const void *);

extern int _set_ctrl(pam_handle_t *, int flags, int argc, const char **argv);
extern int _unix_blankpasswd(pam_handle_t *, const char *user);
extern int _unix_verify_password(pam_handle_t *, const char *, const char *);
extern int unix_getspnam(struct spwd **, const struct passwd *);
extern char *crypt_wrapper(pam_handle_t *, const char *, const char *);
extern char *do_crypt(pam_handle_t *, const char *);

/* Helper function around getlogin() */
static inline char *pam_tcb_getlogin(void)
{
	char *login = getlogin();
	if (!login)
		return "";
	return login;
}

#endif
