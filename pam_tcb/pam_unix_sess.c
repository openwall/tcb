#include <unistd.h>

#include <security/_pam_macros.h>
#define PAM_SM_SESSION
#ifndef LINUX_PAM
#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

#include "support.h"

/*
 * The open session entry point.
 */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	const char *user, *service;
	int retval;

	D(("called"));

	if (!_set_ctrl(flags, argc, argv))
		return PAM_ABORT;

	retval = pam_get_item(pamh, PAM_USER, (const void **)&user);
	if (retval != PAM_SUCCESS || !user) {
		_log_err(LOG_ALERT, "Unable to identify user");
		return PAM_SESSION_ERR;	/* How did we get authenticated with
					   no username?! */
	}

	retval = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
	if (retval != PAM_SUCCESS || !service) {
		_log_err(LOG_ALERT, "Unable to identify service");
		return PAM_SESSION_ERR;
	}

	_log_err(LOG_INFO, "%s: Session opened for %s by %s(uid=%u)",
	    service, user, getlogin() ?: "", getuid());

	return PAM_SUCCESS;
}

/*
 * The close session entry point.
 */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	const char *user, *service;
	int retval;

	D(("called"));

	if (!_set_ctrl(flags, argc, argv))
		return PAM_ABORT;

	retval = pam_get_item(pamh, PAM_USER, (const void **)&user);
	if (retval != PAM_SUCCESS || !user) {
		_log_err(LOG_ALERT, "Unable to identify user");
		return PAM_SESSION_ERR;	/* How did we get authenticated with
					   no username?! */
	}

	retval = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
	if (retval != PAM_SUCCESS || !service) {
		_log_err(LOG_ALERT, "Unable to identify service");
		return PAM_SESSION_ERR;
	}

	_log_err(LOG_INFO, "%s: Session closed for %s", service, user);

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
