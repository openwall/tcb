#include <ctype.h>
#include <unistd.h>
#include <syslog.h>

#include <security/_pam_macros.h>
#define PAM_SM_AUTH
#include <security/pam_modules.h>
#if !defined(__LIBPAM_VERSION) && !defined(__LINUX_PAM__)
# include <security/pam_appl.h>
#endif

#include "attribute.h"
#include "support.h"

#define DATA_AUTH_RETVAL		"-UN*X-AUTH-RETVAL"

static void retval_cleanup(unused pam_handle_t * pamh, void *data,
    unused int error_status)
{
	free(data);
}

/*
 * The authentication entry point.
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	int retval, *retval_data;
	const char *user, *pass = NULL;

	D(("called"));

	if (!_set_ctrl(pamh, flags, argc, argv))
		return PAM_ABORT;

	/* failed malloc is ok */
	retval_data = malloc(sizeof(*retval_data));

	/* get the username */
	retval = pam_get_user(pamh, &user, NULL);
	if (retval == PAM_SUCCESS) {
		/*
		 * Various libraries at various times have had bugs related to
		 * '+' or '-' as the first character of a username. Don't take
		 * any chances here. Require that the username starts with a
		 * letter.
		 */
		if (!user || !isalpha((int)(unsigned char)*user)) {
			if (user && on(UNIX_AUDIT))
				pam_syslog(pamh, LOG_ERR,
				    "Bad username: %s", user);
			else
				pam_syslog(pamh, LOG_ERR, "Bad username");
			user = "UNKNOWN USER";
			retval = PAM_USER_UNKNOWN;
			goto out_save_retval;
		}
		if (on(UNIX_AUDIT))
			pam_syslog(pamh, LOG_DEBUG,
			    "Username obtained: %s", user);
	} else {
		D(("trouble reading username"));
		user = "UNKNOWN USER";
#if defined(PAM_CONV_AGAIN) && defined(PAM_INCOMPLETE)
		if (retval == PAM_CONV_AGAIN) {
			D(("pam_get_user: conv() function is not ready yet"));
			/*
			 * It is safe to resume this function so we translate
			 * this retval to the value that indicates we're happy
			 * to resume.
			 */
			retval = PAM_INCOMPLETE;
		}
#endif /* defined(PAM_CONV_AGAIN) && defined(PAM_INCOMPLETE) */
		goto out_save_retval;
	}

	/* if this user does not have a password... */
	if (_unix_blankpasswd(pamh, user)) {
		D(("user '%s' has blank password", user));
		retval = PAM_SUCCESS;
		goto out_save_retval;
	}

	retval = pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

	if (retval != PAM_SUCCESS) {
#if defined(PAM_CONV_AGAIN) && defined(PAM_INCOMPLETE)
		if (retval == PAM_CONV_AGAIN) {
			pam_syslog(pamh, LOG_CRIT,
			    "Unable to identify password");
		} else {
			D(("conversation function is not ready yet"));
			/*
			 * It is safe to resume this function so we translate
			 * this retval to the value that indicates we're happy
			 * to resume.
			 */
			retval = PAM_INCOMPLETE;
		}
#endif /* defined(PAM_CONV_AGAIN) && defined(PAM_INCOMPLETE) */
		pass = NULL;
		free(retval_data);
		return retval;
	}

	D(("user=%s, password=[%s]", user, pass));

	retval = _unix_verify_password(pamh, user, pass);

	if (retval == PAM_AUTHINFO_UNAVAIL)
		user = "UNKNOWN USER";

out_save_retval:
	if (on(UNIX_LIKE_AUTH) && retval_data) {
		D(("recording return code for next time [%d]", retval));
		*retval_data = retval;
		pam_set_data(pamh, DATA_AUTH_RETVAL,
		    (void *)retval_data, retval_cleanup);
	}

	if (retval == PAM_SUCCESS || !pass
#ifndef FAIL_RECORD
	    || *pass || off(UNIX_NOLOG_BLANK)
#endif
	    ) {
		pam_syslog(pamh, retval == PAM_SUCCESS ? LOG_INFO : LOG_NOTICE,
		    "Authentication %s for %s from %s(uid=%u)",
		    retval == PAM_SUCCESS ? "passed" : "failed", user,
		    getlogin() ?: "", getuid());
	}

	D(("done [%s]", pam_strerror(pamh, retval)));

	return retval;
}

/*
 * The credential setting entry point.
 *
 * Some people think this should initialize supplementary groups, but
 * this is against the tradition and thus we don't do it.
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	int retval = PAM_SUCCESS;
	const int *retval_data = NULL;

	D(("called"));

	if (!_set_ctrl(pamh, flags, argc, argv))
		return PAM_ABORT;

	if (on(UNIX_LIKE_AUTH)) {
		pam_data_t item;

		D(("recovering return code from auth call"));
		pam_get_data(pamh, DATA_AUTH_RETVAL, &item);
		retval_data = item;
		pam_set_data(pamh, DATA_AUTH_RETVAL, NULL, NULL);
		if (retval_data) {
			retval = *retval_data;
			D(("old retval was %d", retval));
		}
	}

	return retval;
}

#ifdef PAM_STATIC
struct pam_module _pam_unix_auth_modstruct = {
	"pam_unix_auth",
	pam_sm_authenticate,
	pam_sm_setcred,
	NULL,
	NULL,
	NULL,
	NULL
};
#endif
