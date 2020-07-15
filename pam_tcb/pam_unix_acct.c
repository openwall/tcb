#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <pwd.h>
#include <shadow.h>

#include <security/_pam_macros.h>
#define PAM_SM_ACCOUNT
#include <security/pam_modules.h>
#if !defined(__LIBPAM_VERSION) && !defined(__LINUX_PAM__)
# include <security/pam_appl.h>
#endif

#include "support.h"

enum {
	ACCT_0 = 0,
	ACCT_1,
	ACCT_2,
	ACCT_3,
	ACCT_4,
	ACCT_5,
	ACCT_6,
	ACCT_7,
	ACCT_SUCCESS = 255
};

static int acct_shadow(unused pam_handle_t *pamh, const void *void_user)
{
	int daysleft;
	time_t curdays;
	const char *user = void_user;
	struct passwd *pw;
	struct spwd *spw = NULL;

	pw = getpwnam(user);
	endpwent();
	if (!pw)
		return ACCT_1; /* shouldn't happen */
	if (on(UNIX_PASSWD) && strcmp(pw->pw_passwd, "x")
	    && strcmp(pw->pw_passwd, "*NP*"))
		return ACCT_SUCCESS;

	if (unix_getspnam(&spw, pw))
		return ACCT_1;

	if (!spw)
		return ACCT_2;

	curdays = time(NULL) / (60 * 60 * 24);
	D(("today is %d, last change %d", curdays, spw->sp_lstchg));
	if ((curdays > spw->sp_expire) && (spw->sp_expire != -1))
		return ACCT_3;

	if ((curdays > (spw->sp_lstchg + spw->sp_max + spw->sp_inact)) &&
	    (spw->sp_max != -1) && (spw->sp_inact != -1) &&
	    (spw->sp_lstchg != 0))
		return ACCT_4;

	D(("when was the last change"));
	if (spw->sp_lstchg == 0)
		return ACCT_5;

	if (((spw->sp_lstchg + spw->sp_max) < curdays) &&
	    (spw->sp_max != -1))
		return ACCT_6;

	if ((curdays > (spw->sp_lstchg + spw->sp_max - spw->sp_warn)) &&
	    (spw->sp_max != -1) && (spw->sp_warn != -1)) {
		daysleft = (spw->sp_lstchg + spw->sp_max) - curdays;
		return ACCT_7 + 256 * daysleft;
	}

	return ACCT_SUCCESS;
}

/*
 * The account management entry point.
 */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	pam_item_t item;
	const char *user;
	int retval, daysleft = 0;
	struct passwd *pw;

	D(("called"));

	if (!_set_ctrl(pamh, flags, argc, argv))
		return PAM_ABORT;
	set(UNIX_SHADOW);

	retval = pam_get_item(pamh, PAM_USER, &item);
	user = item;
	D(("user = `%s'", user));
	if (retval != PAM_SUCCESS || !user) {
		pam_syslog(pamh, LOG_ALERT, "Unable to identify user");
		return PAM_USER_UNKNOWN;
	}

	pw = getpwnam(user);
	endpwent();
	if (!pw) {
		pam_syslog(pamh, LOG_ALERT, "Unable to identify user");
		return PAM_USER_UNKNOWN;
	}

	if (off(UNIX_FORKAUTH))
		retval = acct_shadow(pamh, user);
	else
		retval = _unix_fork(pamh, acct_shadow, user);
	if (retval > 255) {
		daysleft = retval / 256;
		retval %= 256;
	}

	switch (retval) {
	case ACCT_SUCCESS:
		return PAM_SUCCESS;

	case ACCT_1:
		return PAM_AUTHINFO_UNAVAIL;

	case ACCT_2:
		return PAM_CRED_INSUFFICIENT;

	case ACCT_3:
		pam_syslog(pamh, LOG_NOTICE,
		    "Account %s has expired (account expired)", user);
		if (off(UNIX__QUIET))
			pam_error(pamh, "%s", MESSAGE_ACCT_EXPIRED);
		D(("account expired (1)"));
		return PAM_ACCT_EXPIRED;

	case ACCT_4:
		pam_syslog(pamh, LOG_NOTICE,
		    "Account %s has expired (failed to change password)",
		    user);
		if (off(UNIX__QUIET))
			pam_error(pamh, "%s", MESSAGE_ACCT_EXPIRED);
		D(("account expired (2)"));
		return PAM_ACCT_EXPIRED;

	case ACCT_5:
		pam_syslog(pamh, LOG_INFO,
		    "Expired password for %s (root enforced)", user);
		if (off(UNIX__QUIET))
			pam_error(pamh, "%s", MESSAGE_PASS_ENFORCED);
		D(("need a new password (1)"));
		return PAM_NEW_AUTHTOK_REQD;

	case ACCT_6:
		pam_syslog(pamh, LOG_INFO,
		    "Expired password for %s (password aged)", user);
		if (off(UNIX__QUIET))
			pam_error(pamh, "%s", MESSAGE_PASS_EXPIRED);
		D(("need a new password (2)"));
		return PAM_NEW_AUTHTOK_REQD;

	case ACCT_7:
		pam_syslog(pamh, LOG_INFO,
		    "Password for %s will expire in %d day%s",
		    user, daysleft, daysleft == 1 ? "" : "s");
		if (off(UNIX__QUIET))
			pam_info(pamh, MESSAGE_WARN_EXPIRE(daysleft));
		return PAM_SUCCESS;

	default:
		pam_syslog(pamh, LOG_CRIT,
		    "Unknown return code from acct_shadow (%d)", retval);
	}

	return PAM_ABORT;
}

#ifdef PAM_STATIC
struct pam_module _pam_unix_acct_modstruct = {
	"pam_unix_acct",
	NULL,
	NULL,
	pam_sm_acct_mgmt,
	NULL,
	NULL,
	NULL
};
#endif
