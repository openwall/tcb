#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <pwd.h>
#include <shadow.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>

#include <security/_pam_macros.h>
#define PAM_SM_PASSWORD
#ifndef LINUX_PAM
#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

#include "tcb.h"

#include "attribute.h"
#include "support.h"
#include "yppasswd.h"

#if !(((__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 1)) || (__GLIBC__ > 2))
extern int getrpcport(const char *host, unsigned long prognum,
    unsigned long versnum, unsigned int proto);
#endif

#define DATA_OLD_AUTHTOK		"-UN*X-OLD-PASS"
#define DATA_NEW_AUTHTOK		"-UN*X-NEW-PASS"

#define TRIES				3

#define TMP_SUFFIX			".tmp"
#define PASSWD_TMP_FILE			"/etc/passwd" TMP_SUFFIX

static char *get_nis_server(void)
{
	char *master;
	char *domain;
	int port, result;

	if ((result = yp_get_default_domain(&domain)) != 0) {
		_log_err(LOG_WARNING, "Unable to get local yp domain: %s",
		    yperr_string(result));
		return NULL;
	}

	if ((result = yp_master(domain, "passwd.byname", &master)) != 0) {
		_log_err(LOG_WARNING,
		    "Unable to find the master yp server: %s",
		    yperr_string(result));
		return NULL;
	}

	port = getrpcport(master, YPPASSWDPROG, YPPASSWDPROC_UPDATE,
	    IPPROTO_UDP);

	if (port == 0) {
		_log_err(LOG_WARNING,
		    "yppasswdd not running on NIS master host");
		return NULL;
	}

	if (port >= IPPORT_RESERVED) {
		_log_err(LOG_WARNING, "yppasswdd running on illegal port");
		return NULL;
	}

	return master;
}

static int cpmod(const char *old, const char *new)
{
	struct stat st;

	if (stat(old, &st))
		return -1;
	if (chmod(new, S_IRUSR))
		return -1;
	if (chown(new, st.st_uid, st.st_gid))
		return -1;
	if (chmod(new, st.st_mode))
		return -1;
	return 0;
}

static int update_passwd(const char *forwho, const char *towhat)
{
	FILE *newf, *oldf;
	int fd;
	int error;
	int fieldnum, charnum, thisline, namelen;
	int c;

	D(("called"));

	fd = open(PASSWD_TMP_FILE, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR);
	if (fd < 0)
		return PAM_AUTHTOK_ERR;
	newf = fdopen(fd, "w");
	if (!newf) {
		close(fd);
		unlink(PASSWD_TMP_FILE);
		return PAM_AUTHTOK_ERR;
	}

	oldf = fopen(PASSWD_FILE, "r");
	if (!oldf || cpmod(PASSWD_FILE, PASSWD_TMP_FILE) != 0) {
		fclose(newf);
		if (oldf)
			fclose(oldf);
		unlink(PASSWD_TMP_FILE);
		return PAM_AUTHTOK_ERR;
	}

	error = 0;
	fieldnum = 0;
	charnum = 0;
	thisline = 1;
	namelen = strlen(forwho);

	/* This loop may look weird, but it doesn't allocate any buffers
	 * and doesn't impose any limits on any field's length. */
	while (1) {
		c = fgetc(oldf);
		if (c == EOF)
			break;
		/* does this line begin with forwho? */
		if (fieldnum == 0 && charnum < namelen &&
		    c != forwho[charnum])
			thisline = 0;
		if (fieldnum == 0 && charnum == namelen && c != ':')
			thisline = 0;

		if ((!thisline || fieldnum != 1) && putc(c, newf) == EOF) {
			error = 1;
			break;
		}
		if (c == ':') {
			if (fieldnum == 0)
				if (thisline && forwho[charnum])
					thisline = 0;
			if (fieldnum == 1 && thisline) {
				if (fputs(towhat, newf) == EOF ||
				    putc(':', newf) == EOF) {
					error = 1;
					break;
				}
			}
			fieldnum++;
		}
		charnum++;
		if (c == '\n') {
			fieldnum = 0;
			charnum = 0;
			thisline = 1;
		}
	}

	if (ferror(newf))
		error = 1;
	if (fclose(newf))
		error = 1;
	if (ferror(oldf))
		error = 1;
	if (fclose(oldf))
		error = 1;
	if (!error && rename(PASSWD_TMP_FILE, PASSWD_FILE))
		error = 1;

	if (error) {
		_log_err(LOG_CRIT, "Failed to update %s: %s",
		    PASSWD_FILE, strerror(errno));
		unlink(PASSWD_TMP_FILE);
		return PAM_AUTHTOK_ERR;
	}

	return PAM_SUCCESS;
}

static int update_shadow(const char *forwho, const char *towhat,
    const char *file)
{
	char *tmpfile;
	FILE *newf, *oldf;
	int fd;
	int error;
	int fieldnum, charnum, thisline, namelen;
	int c;

	D(("called"));

	if (asprintf(&tmpfile, "%s%s", file, TMP_SUFFIX) < 0)
		return PAM_AUTHTOK_ERR;

	fd = open(tmpfile, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR);
	if (fd < 0) {
		free(tmpfile);
		return PAM_AUTHTOK_ERR;
	}
	newf = fdopen(fd, "w");
	if (!newf) {
		close(fd);
		unlink(tmpfile);
		free(tmpfile);
		return PAM_AUTHTOK_ERR;
	}

	oldf = fopen(file, "r");
	if (!oldf ||
	    tcb_is_suspect(fileno(oldf)) || cpmod(file, tmpfile) != 0) {
		fclose(newf);
		if (oldf)
			fclose(oldf);
		unlink(tmpfile);
		free(tmpfile);
		return PAM_AUTHTOK_ERR;
	}

	error = 0;
	fieldnum = 0;
	charnum = 0;
	thisline = 1;
	namelen = strlen(forwho);

	/* This loop may look weird, but it doesn't allocate any buffers
	 * and doesn't impose any limits on any field's length. */
	while (1) {
		c = fgetc(oldf);
		if (c == EOF)
			break;
		/* does this line begin with forwho? */
		if (fieldnum == 0 && charnum < namelen &&
		    c != forwho[charnum])
			thisline = 0;
		if (fieldnum == 0 && charnum == namelen && c != ':')
			thisline = 0;

		if ((!thisline || (fieldnum != 1 && fieldnum != 2)) &&
		    putc(c, newf) == EOF) {
			error = 1;
			break;
		}
		if (c == ':') {
			if (fieldnum == 0)
				if (thisline && forwho[charnum])
					thisline = 0;
			if (fieldnum == 1 && thisline) {
				if (fputs(towhat, newf) == EOF ||
				    putc(':', newf) == EOF) {
					error = 1;
					break;
				}
			}
			if (fieldnum == 2 && thisline) {
				char *timestr;

				if (asprintf(&timestr, "%d:",
				    (int)(time(NULL) / (60 * 60 * 24))) < 0)
					timestr = NULL;
				if (!timestr ||
				    fputs(timestr, newf) == EOF) {
					if (timestr)
						free(timestr);
					error = 1;
					break;
				}
				free(timestr);
			}
			fieldnum++;
		}
		charnum++;
		if (c == '\n') {
			fieldnum = 0;
			charnum = 0;
			thisline = 1;
		}
	}

	if (ferror(newf))
		error = 1;
	if (fclose(newf))
		error = 1;
	if (ferror(oldf))
		error = 1;
	if (fclose(oldf))
		error = 1;
	if (!error && rename(tmpfile, file))
		error = 1;

	if (error)
		unlink(tmpfile);
	free(tmpfile);

	if (error) {
		_log_err(LOG_CRIT, "Failed to update %s: %s",
		    file, strerror(errno));
		return PAM_AUTHTOK_ERR;
	}

	return PAM_SUCCESS;
}

static int update_nis(unused const char *forwho, const char *fromwhat,
    char *towhat, struct passwd *pw)
{
	struct timeval timeout;
	struct yppasswd yppw;
	char *master;
	CLIENT *client;
	enum clnt_stat result;
	int status;

	D(("called"));

	/* Make RPC call to NIS server */
	master = get_nis_server();
	if (!master)
		return PAM_TRY_AGAIN;

	/* Initialize password information */
	yppw.newpw.pw_passwd = pw->pw_passwd;
	yppw.newpw.pw_name = pw->pw_name;
	yppw.newpw.pw_uid = pw->pw_uid;
	yppw.newpw.pw_gid = pw->pw_gid;
	yppw.newpw.pw_gecos = pw->pw_gecos;
	yppw.newpw.pw_dir = pw->pw_dir;
	yppw.newpw.pw_shell = pw->pw_shell;
	yppw.oldpass = (char *)fromwhat;
	yppw.newpw.pw_passwd = towhat;

	D(("set password %s for %s", yppw.newpw.pw_passwd, forwho));

	/*
	 * The yppasswd.x file said `unix authentication required',
	 * so I added it. This is the only reason it is in here.
	 * My yppasswdd doesn't use it, but maybe some others out there
	 * do.                                        --okir
	 */
	client = clnt_create(master, YPPASSWDPROG, YPPASSWDVERS, "udp");
	client->cl_auth = authunix_create_default();
	memset(&status, 0, sizeof(status));
	timeout.tv_sec = 25;
	timeout.tv_usec = 0;
	result = clnt_call(client, YPPASSWDPROC_UPDATE,
	    (xdrproc_t)xdr_yppasswd, (char *)&yppw,
	    (xdrproc_t)xdr_int, (char *)&status, timeout);

	status |= result;
	if (status) {
		_log_err(LOG_ERR, "Failed to change NIS password on %s%s%s",
		    master,
		    result ? ": " : "",
		    result ? clnt_sperrno(result) : "");
	}
	_log_err(LOG_INFO, "Password%s changed on %s",
	    status ? " not" : "", master);

	auth_destroy(client->cl_auth);
	clnt_destroy(client);

	if (status)
		return PAM_TRY_AGAIN;

	return PAM_SUCCESS;
}

static char *get_pwfile(const char *forwho)
{
	if (pam_unix_param.write_to == WRITE_TCB) {
		char *file;
		if (asprintf(&file, TCB_FMT, forwho) < 0)
			file = NULL;
		return file;
	}
	if (pam_unix_param.write_to == WRITE_SHADOW)
		return strdup(SHADOW_FILE);
	return strdup(PASSWD_FILE);
}

static int do_setpass(const char *forwho, const char *fromwhat, char *towhat)
{
	struct passwd *pw = NULL;
	char *file;
	int retval;
	int need_passwd, need_lckpwdf;

	D(("called"));

	pw = getpwnam(forwho);
	endpwent();
	if (!pw)
		return PAM_AUTHTOK_ERR;

	if (pam_unix_param.write_to == WRITE_NIS)
		return update_nis(forwho, fromwhat, towhat, pw);

	file = get_pwfile(forwho);
	if (!file)
		return PAM_BUF_ERR;

	need_passwd = (pam_unix_param.write_to == WRITE_SHADOW ||
	    pam_unix_param.write_to == WRITE_TCB) &&
	    strcmp(pw->pw_passwd, "x");
	D(("need_passwd=%d", need_passwd));
	need_lckpwdf = pam_unix_param.write_to == WRITE_PASSWD ||
	    pam_unix_param.write_to == WRITE_SHADOW || need_passwd;
	D(("need_lckpwdf=%d", need_lckpwdf));
	if (need_lckpwdf && geteuid()) {
		free(file);
		return PAM_CRED_INSUFFICIENT;
	}

	retval = PAM_AUTHTOK_LOCK_BUSY;
	if (need_lckpwdf && lckpwdf())
		goto out;
	if (pam_unix_param.write_to == WRITE_TCB) {
		if (tcb_drop_priv(forwho)) {
			retval = PAM_CRED_INSUFFICIENT;
			goto out_ulckpwdf;
		}
		if (lckpwdf_tcb(file)) {
			if (errno == EACCES)
				retval = PAM_CRED_INSUFFICIENT;
			tcb_gain_priv();
			goto out_ulckpwdf;
		}
	}
	if (pam_unix_param.write_to == WRITE_PASSWD)
		retval = update_passwd(forwho, towhat);
	else {
		retval = update_shadow(forwho, towhat, file);
		if (pam_unix_param.write_to == WRITE_TCB) {
			ulckpwdf_tcb();
			tcb_gain_priv();
		}
		if (retval == PAM_SUCCESS && need_passwd)
			retval = update_passwd(forwho, "x");
	}

out_ulckpwdf:
	if (need_lckpwdf)
		ulckpwdf();

out:
	free(file);
	return retval;
}

static int unix_verify_shadow(const char *user)
{
	struct passwd *pw = NULL;	/* Password and shadow password */
	struct spwd *spw = NULL;	/* file entries for the user. */
	time_t curdays;

	D(("called"));

	pw = getpwnam(user);
	endpwent();
	if (!pw)
		return PAM_AUTHINFO_UNAVAIL;

	D(("before unix_getspnam()"));
	if (unix_getspnam(&spw, pw) == 1)
		/* If we're here, we don't seem to use shadow passwords. */
		return PAM_SUCCESS;
	if (!spw)
		return PAM_AUTHINFO_UNAVAIL;
	D(("after unix_getspnam()"));

	/* We have the user's information, now let's check if their
	 * password or account has expired. */
	if (off(UNIX__IAMROOT)) {
		/* Get the current number of days since 1970. */
		curdays = time(NULL) / (60 * 60 * 24);
		if (curdays < spw->sp_lstchg + spw->sp_min &&
		    spw->sp_min != -1)
			/* too early */
			return PAM_AUTHTOK_ERR;
		else
		if (curdays > spw->sp_lstchg + spw->sp_max + spw->sp_inact &&
		    spw->sp_max != -1 && spw->sp_inact != -1 &&
		    spw->sp_lstchg != 0)
			/* too late */
			return PAM_ACCT_EXPIRED;
		else
		if (curdays > spw->sp_expire && spw->sp_expire != -1)
			/* account expired */
			return PAM_ACCT_EXPIRED;
	}

	return PAM_SUCCESS;
}

static int unix_approve_pass(pam_handle_t *pamh,
    const char *oldpass, const char *newpass)
{
	D(("called"));
	D(("&oldpass=%p &newpass=%p", oldpass, newpass));
	D(("oldpass=[%s] newpass=[%s]", oldpass, newpass));

	if (!newpass || (oldpass && !strcmp(oldpass, newpass))) {
		if (on(UNIX_DEBUG))
			_log_err(LOG_DEBUG, "Bad new authentication token");
		_make_remark(pamh, PAM_ERROR_MSG,
		    newpass ? MESSAGE_PASS_SAME : MESSAGE_PASS_NONE);
		return PAM_AUTHTOK_ERR;
	}

	return PAM_SUCCESS;
}

static int unix_prelim(pam_handle_t *pamh, const char *user)
{
	int lctrl[OPT_SIZE];
	char *greeting;
	const void *item;
	const char *oldpass, *service;
	int retval = PAM_SUCCESS;

	D(("called"));

	if (_unix_blankpasswd(user))
		goto out;

	if (asprintf(&greeting, MESSAGE_CHANGING, user) < 0) {
		_log_err(LOG_CRIT, "Out of memory");
		return PAM_BUF_ERR;
	}

	if (off(UNIX__IAMROOT)) {
		memcpy(lctrl, pam_unix_param.ctrl, sizeof(lctrl));
		set(UNIX__OLD_PASSWD);
		retval = _unix_read_password(pamh, greeting,
		    PROMPT_OLDPASS, NULL,
		    DATA_OLD_AUTHTOK, &oldpass);
		free(greeting);
		memcpy(pam_unix_param.ctrl, lctrl,
		    sizeof(pam_unix_param.ctrl));

		if (retval != PAM_SUCCESS) {
			_log_err(LOG_NOTICE,
			    "Current password not obtained");
			return retval;
		}

		/* verify that this is the password for this user */
		retval = _unix_verify_password(pamh, user, oldpass);
		if (retval != PAM_SUCCESS) {
			D(("authentication failed"));
			if (retval == PAM_AUTHINFO_UNAVAIL)
				user = "UNKNOWN USER";
			goto out;
		}
	} else {
		D(("process run by root so no authentication is done"));
		oldpass = NULL;
		retval = PAM_SUCCESS;
	}

	retval = pam_set_item(pamh, PAM_OLDAUTHTOK, (const void *)oldpass);
	if (retval != PAM_SUCCESS)
		_log_err(LOG_CRIT, "Failed to set PAM_OLDAUTHTOK");

	retval = unix_verify_shadow(user);
	if (retval == PAM_AUTHTOK_ERR) {
		if (off(UNIX__IAMROOT))
			_make_remark(pamh, PAM_ERROR_MSG, MESSAGE_TOOSOON);
		else
			retval = PAM_SUCCESS;
	}

out:
#ifdef FAIL_RECORD
	if (retval != PAM_SUCCESS)
		return retval;
#endif

	if (on(UNIX__IAMROOT))
		return retval;

	if (pam_get_item(pamh, PAM_SERVICE, &item) != PAM_SUCCESS)
		item = NULL;
	service = item;
	_log_err(retval == PAM_SUCCESS ? LOG_INFO : LOG_NOTICE,
	    "%s: Authentication %s for %s from %s(uid=%u)"
	    ", for password management",
	    service ?: "UNKNOWN SERVICE",
	    retval == PAM_SUCCESS ? "passed" : "failed", user,
	    getlogin() ?: "", getuid());

	return retval;
}

/*
 * The password change entry point.
 */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	int retval, retry;
	char oldprefix[HASH_PREFIX_SIZE];
	/* <DO NOT free() THESE> */
	const void *item;
	const char *user, *oldpass, *newpass;
	/* </DO NOT free() THESE> */
	char *newhash;
	const char *service;

	D(("called"));

	if (!_set_ctrl(flags, argc, argv))
		return PAM_ABORT;

	/* get the username */
	retval = pam_get_user(pamh, &user, PROMPT_USER);
	if (retval == PAM_SUCCESS) {
		/*
		 * Various libraries at various times have had bugs related to
		 * '+' or '-' as the first character of a username. Don't take
		 * any chances here. Require that the username starts with a
		 * letter.
		 */
		if (!user || !isalpha((int)(unsigned char)*user)) {
			if (user && on(UNIX_AUDIT))
				_log_err(LOG_ERR, "Bad username: %s", user);
			else
				_log_err(LOG_ERR, "Bad username");
			return PAM_USER_UNKNOWN;
		}
		if (on(UNIX_AUDIT))
			_log_err(LOG_DEBUG, "Username obtained: %s", user);
	} else {
		if (on(UNIX_DEBUG))
			_log_err(LOG_DEBUG, "Unable to identify user");
		return retval;
	}

	if (!_unix_user_in_db(user, oldprefix)) {
		_log_err(LOG_DEBUG,
		    "Unable to find user in the selected database");
		return PAM_USER_UNKNOWN;
	}
	if (*oldprefix == '*' && strncmp(oldprefix, "*NP*", 4)) {
		_log_err(LOG_DEBUG,
		    "User \"%s\" does not have a modifiable password", user);
		return PAM_AUTHTOK_ERR;
	}

	if (on(UNIX__PRELIM))
		return unix_prelim(pamh, user);
	if (off(UNIX__UPDATE))
		return PAM_ABORT;

	D(("do update"));

	/*
	 * Get the old token back. NULL was ok only if root (at this
	 * point we assume that this has already been enforced on a
	 * previous call to this function).
	 */
	if (off(UNIX_NOT_SET_PASS)) {
		retval = pam_get_item(pamh, PAM_OLDAUTHTOK, &item);
	} else {
		retval = pam_get_data(pamh, DATA_OLD_AUTHTOK, &item);
		if (retval == PAM_NO_MODULE_DATA) {
			retval = PAM_SUCCESS;
			item = NULL;
		}
	}
	oldpass = item;
	D(("oldpass=[%s]", oldpass));

	if (retval != PAM_SUCCESS) {
		_log_err(LOG_NOTICE, "User not authenticated");
		return retval;
	}

	/* check account expiration */
	retval = unix_verify_shadow(user);
	if (retval != PAM_SUCCESS) {
		if (retval == PAM_ACCT_EXPIRED)
			_log_err(LOG_NOTICE, "Account expired");
		return retval;
	}

	D(("get new password now"));

	retval = PAM_AUTHTOK_ERR;
	retry = 0;
	newhash = NULL;
	while (retval != PAM_SUCCESS && retry++ < TRIES) {
		int old_authtok_usage = pam_unix_param.authtok_usage;
		/*
		 * use_authtok is to force the use of a previously entered
		 * password, needed for pluggable password strength checking.
		 */
		if (on(UNIX_USE_AUTHTOK))
			pam_unix_param.authtok_usage = USE_FORCED;
		retval = _unix_read_password(pamh, NULL,
		    PROMPT_NEWPASS1, PROMPT_NEWPASS2,
		    DATA_NEW_AUTHTOK, &newpass);
		pam_unix_param.authtok_usage = old_authtok_usage;

		D(("returned to pam_sm_chauthtok"));

		if (retval != PAM_SUCCESS) {
			if (on(UNIX_DEBUG)) {
				_log_err(LOG_ERR,
				    "New password not obtained");
			}
			return retval;
		}

		/*
		 * At this point we know who the user is and what they
		 * propose as their new password. Verify that the new
		 * password is acceptable.
		 */
		if (newpass && !*newpass)
			newpass = NULL;
		retval = unix_approve_pass(pamh, oldpass, newpass);
	}

	if (retval != PAM_SUCCESS) {
		_log_err(LOG_NOTICE, "New password not acceptable");
		_pam_overwrite((char *)newpass);
		_pam_overwrite((char *)oldpass);
		return retval;
	}

	/*
	 * By reaching here we have approved the passwords and must now
	 * rebuild the password database file(s).
	 */

	/* First we hash the new password and forget the plaintext. */
	newhash = do_crypt(newpass);
	_pam_overwrite((char *)newpass);

	D(("password processed"));

	/* update the password database(s) -- race conditions? */
	if (newhash)
		retval = do_setpass(user, oldpass, newhash);
	else
		retval = PAM_BUF_ERR;
	_pam_overwrite((char *)oldpass);
	_pam_delete(newhash);

	if (retval == PAM_SUCCESS) {
		if (pam_get_item(pamh, PAM_SERVICE, &item) != PAM_SUCCESS)
			item = NULL;
		service = item;
		_log_err(LOG_INFO,
		    "%s: Password for %s changed by %s(uid=%u)",
		    service ?: "UNKNOWN SERVICE",
		    user, getlogin() ?: "", getuid());
	}

	D(("retval was %d", retval));

	return retval;
}

#ifdef PAM_STATIC
struct pam_module _pam_unix_passwd_modstruct = {
	"pam_unix_passwd",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	pam_sm_chauthtok
};
#endif
