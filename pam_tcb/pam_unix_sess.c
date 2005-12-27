#include <unistd.h>
#include <syslog.h>

#include <security/_pam_macros.h>
#define PAM_SM_SESSION
#include <security/pam_modules.h>
#if !defined(__LIBPAM_VERSION) && !defined(__LINUX_PAM__)
# include <security/pam_appl.h>
#endif

#include "support.h"

/*
 * The open session entry point.
 */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	pam_item_t item;
	const char *user;
	int retval;

	D(("called"));

	if (!_set_ctrl(pamh, flags, argc, argv))
		return PAM_ABORT;

	retval = pam_get_item(pamh, PAM_USER, &item);
	user = item;
	if (retval != PAM_SUCCESS || !user) {
		pam_syslog(pamh, LOG_ALERT, "Unable to identify user");
		return PAM_SESSION_ERR;	/* How did we get authenticated with
					   no username?! */
	}

	pam_syslog(pamh, LOG_INFO, "Session opened for %s by %s(uid=%u)",
	    user, getlogin() ?: "", getuid());

	return PAM_SUCCESS;
}

/*
 * The close session entry point.
 */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	pam_item_t item;
	const char *user;
	int retval;

	D(("called"));

	if (!_set_ctrl(pamh, flags, argc, argv))
		return PAM_ABORT;

	retval = pam_get_item(pamh, PAM_USER, &item);
	user = item;
	if (retval != PAM_SUCCESS || !user) {
		pam_syslog(pamh, LOG_ALERT, "Unable to identify user");
		return PAM_SESSION_ERR;	/* How did we get authenticated with
					   no username?! */
	}

	pam_syslog(pamh, LOG_INFO, "Session closed for %s", user);

	return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_unix_session_modstruct = {
	"pam_unix_session",
	NULL,
	NULL,
	NULL,
	pam_sm_open_session,
	pam_sm_close_session,
	NULL
};
#endif
