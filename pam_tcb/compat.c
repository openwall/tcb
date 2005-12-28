#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#if !defined(__LIBPAM_VERSION) && !defined(__LINUX_PAM__)
# include <security/pam_appl.h>
#endif

#include "attribute.h"
#include "support.h"

#ifndef __LINUX_PAM__
/* syslogging function for errors and other information */
void
pam_syslog(pam_handle_t *pamh, int priority, const char *fmt, ...)
{
	int save_errno = errno;
	pam_item_t item;
	const char *service;
	va_list args;
	char *msgbuf;

	if (on(UNIX_NOLOG))
		return;

	if (pam_get_item(pamh, PAM_SERVICE, &item) != PAM_SUCCESS || !item)
		service = "UNKNOWN SERVICE";
	else
		service = item;

	if (on(UNIX_OPENLOG))
		openlog("pam_tcb", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

	va_start(args, fmt);
	errno = save_errno;
	if (vasprintf (&msgbuf, fmt, args) < 0)
		msgbuf = NULL;
	va_end(args);

	if (!msgbuf) {
		syslog (LOG_AUTHPRIV|LOG_CRIT, "%s: %s: vasprintf: %m",
		    "pam_tcb", service);
		if (on(UNIX_OPENLOG))
			closelog();
		return;
	}

	syslog (LOG_AUTHPRIV|priority, "%s: %s: %s",
	    "pam_tcb", service, msgbuf);
	_pam_delete (msgbuf);

	if (on(UNIX_OPENLOG))
		closelog();
}
#ifndef _OPENPAM
int TCB_FORMAT((printf, 4, 5)) TCB_NONNULL((1,4))
pam_prompt(pam_handle_t *pamh, int style, char **response, const char *fmt, ...)
{
	struct pam_message msg;
	struct pam_response *pam_resp = NULL;
	const struct pam_message *pmsg;
	const struct pam_conv *conv;
	const void *convp;
	char   *msgbuf;
	va_list args;
	int     retval;

	if (response)
		*response = NULL;

	retval = pam_get_item(pamh, PAM_CONV, &convp);
	if (retval != PAM_SUCCESS)
		return retval;
	conv = convp;
	if (conv == NULL || conv->conv == NULL)
	{
		pam_syslog(pamh, LOG_ERR, "no conversation function");
		return PAM_SYSTEM_ERR;
	}

	va_start(args, fmt);
	if (vasprintf(&msgbuf, fmt, args) < 0)
	{
		pam_syslog(pamh, LOG_ERR, "asprintf: %m");
		retval = PAM_BUF_ERR;
	}
	va_end(args);

	if (retval != PAM_SUCCESS)
		return retval;

	msg.msg_style = style;
	msg.msg = msgbuf;
	pmsg = &msg;

	retval = conv->conv(1, &pmsg, &pam_resp, conv->appdata_ptr);
	if (retval != PAM_SUCCESS && pam_resp != NULL)
		pam_syslog(pamh, LOG_WARNING,
			   "unexpected response from failed conversation function");
	if (response)
		*response = pam_resp == NULL ? NULL : pam_resp->resp;
	else if (pam_resp && pam_resp->resp)
	{
		_pam_overwrite(pam_resp->resp);
		_pam_drop(pam_resp->resp);
	}
	_pam_overwrite(msgbuf);
	_pam_drop(pam_resp);
	free(msgbuf);
	if (retval != PAM_SUCCESS)
		pam_syslog(pamh, LOG_ERR, "Conversation failure: %s",
			   pam_strerror(pamh, retval));

	return retval;
}
#endif /* !_OPENPAM */
#endif /* !__LINUX_PAM__ */
