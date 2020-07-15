#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <syslog.h>
#include <pwd.h>
#include <shadow.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>

#include <security/_pam_macros.h>
#define PAM_SM_PASSWORD
#include <security/pam_modules.h>
#if !defined(__LIBPAM_VERSION) && !defined(__LINUX_PAM__)
# include <security/pam_appl.h>
#endif

#include "tcb.h"

#include "attribute.h"
#include "support.h"

#define TRIES				3

#define TMP_SUFFIX			".tmp"

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

static int update_file(pam_handle_t *pamh, const char *forwho,
    const char *towhat, const char *towhat2, const char *file,
    int (*filecheck)(int))
{
	FILE *newf = NULL, *oldf = NULL;
	char *tmp_file = NULL;
	int fd;
	int error;
	int fieldnum, charnum, thisline, namelen;
	int retval = PAM_AUTHTOK_ERR;

	D(("called"));

	if (asprintf(&tmp_file, "%s%s", file, TMP_SUFFIX) < 0) {
		pam_syslog(pamh, LOG_CRIT, "Out of memory");
		return PAM_BUF_ERR;
	}

	fd = open(tmp_file, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR);
	if (fd < 0) {
		pam_syslog(pamh, LOG_CRIT,
		    "Error opening %s: %m", tmp_file);
		_pam_drop(tmp_file);
		goto out_update_file;
	}
	if ((newf = fdopen(fd, "w")) == NULL) {
		pam_syslog(pamh, LOG_CRIT,
		    "Error opening %s: %m", tmp_file);
		close(fd);
		fd = -1;
		goto out_update_file;
	}

	if ((oldf = fopen(file, "r")) == NULL) {
		pam_syslog(pamh, LOG_CRIT,
		    "Error opening %s: %m", file);
		goto out_update_file;
	}
	if (filecheck && filecheck(fileno(oldf))) {
		pam_syslog(pamh, LOG_CRIT,
		    "File %s is not sane", file);
		goto out_update_file;
	}
	if (cpmod(file, tmp_file) != 0) {
		pam_syslog(pamh, LOG_CRIT,
		    "Error setting ownership or permissions for %s: %m",
		    tmp_file);
		goto out_update_file;
	}

	error = 0;
	fieldnum = 0;
	charnum = 0;
	thisline = 1;
	namelen = strlen(forwho);

	/* This loop may look weird, but it doesn't allocate any buffers
	 * and doesn't impose any limits on any field's length. */
	while (1) {
		int c = fgetc(oldf);
		if (c == EOF)
			break;
		/* does this line begin with forwho? */
		if (fieldnum == 0 && charnum < namelen &&
		    c != forwho[charnum])
			thisline = 0;
		if (fieldnum == 0 && charnum == namelen && c != ':')
			thisline = 0;

		if ((!thisline
		     || (fieldnum != 1 && (!towhat2 || fieldnum != 2)))
		    && putc(c, newf) == EOF) {
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
			if (fieldnum == 2 && towhat2 && thisline) {
				if (fputs(towhat2, newf) == EOF ||
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

	if (error || ferror(newf) || fflush(newf) || fsync(fd)) {
		pam_syslog(pamh, LOG_CRIT,
		    "Error writing %s: %m", tmp_file);
		goto out_update_file;
	}
	fd = -1;

	if (ferror(oldf)) {
		pam_syslog(pamh, LOG_CRIT,
		    "Error reading %s: %m", file);
		goto out_update_file;
	}

	if (fclose(newf))
		error = 1;
	newf = NULL;
	if (error) {
		pam_syslog(pamh, LOG_CRIT,
		    "Error closing %s: %m", tmp_file);
		goto out_update_file;
	}

	if (fclose(oldf))
		error = 1;
	oldf = NULL;
	if (error) {
		pam_syslog(pamh, LOG_CRIT,
		    "Error closing %s: %m", file);
		goto out_update_file;
	}

	if (rename(tmp_file, file)) {
		pam_syslog(pamh, LOG_CRIT,
		    "Error renaming %s to %s: %m",
		    tmp_file, file);
		goto out_update_file;
	}
	_pam_drop(tmp_file);

	retval = PAM_SUCCESS;

out_update_file:
	if (tmp_file) {
		unlink(tmp_file);
		_pam_drop(tmp_file);
	}
	if (oldf)
		fclose(oldf);
	if (newf)
		fclose(newf);

	if (retval != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR,
		    "Failed to update %s", file);
	}

	return retval;
}

static int update_passwd(pam_handle_t *pamh, const char *forwho,
    const char *towhat)
{
	return update_file(pamh, forwho, towhat, NULL, PASSWD_FILE, NULL);
}

static int update_shadow(pam_handle_t *pamh, const char *forwho,
    const char *towhat, const char *file)
{
	int retval;
	char *timestr;

	if (asprintf(&timestr, "%d", (int)(time(NULL) / (60 * 60 * 24))) < 0) {
		pam_syslog(pamh, LOG_CRIT, "Out of memory");
		return PAM_BUF_ERR;
	}
	retval = update_file(pamh, forwho, towhat, timestr, file, tcb_is_suspect);
	_pam_drop(timestr);
	return retval;
}

static char *get_pwfile(const char *forwho)
{
	char *file;

	switch (pam_unix_param.write_to) {
	case WRITE_TCB:
		if (asprintf(&file, TCB_FMT, forwho) < 0)
			file = NULL;
		return file;

	case WRITE_SHADOW:
		return strdup(SHADOW_FILE);

	default:
		return strdup(PASSWD_FILE);
	}
}

static int do_setpass(pam_handle_t *pamh, const char *forwho, char *towhat)
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

	file = get_pwfile(forwho);
	if (!file) {
		pam_syslog(pamh, LOG_CRIT, "Out of memory");
		return PAM_BUF_ERR;
	}

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
		retval = update_passwd(pamh, forwho, towhat);
	else {
		retval = update_shadow(pamh, forwho, towhat, file);
		if (pam_unix_param.write_to == WRITE_TCB) {
			ulckpwdf_tcb();
			tcb_gain_priv();
		}
		if (retval == PAM_SUCCESS && need_passwd)
			retval = update_passwd(pamh, forwho, "x");
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
			pam_syslog(pamh, LOG_DEBUG,
			    "Bad new authentication token");
		if (off(UNIX__QUIET))
			pam_error(pamh, "%s",
			    newpass ? MESSAGE_PASS_SAME : MESSAGE_PASS_NONE);
		return PAM_AUTHTOK_ERR;
	}

	return PAM_SUCCESS;
}

static int unix_prelim(pam_handle_t *pamh, const char *user)
{
	int retval = PAM_SUCCESS;

	D(("called"));

	if (_unix_blankpasswd(pamh, user))
		goto out;

	if (off(UNIX__IAMROOT)) {
		const char *oldpass;

		if (off(UNIX__QUIET)) {
			retval = pam_info(pamh, MESSAGE_CHANGING, user);
			if (retval != PAM_SUCCESS)
				return retval;
		}
		retval = pam_get_authtok(pamh, PAM_OLDAUTHTOK, &oldpass, NULL);

		if (retval != PAM_SUCCESS) {
			pam_syslog(pamh, LOG_NOTICE,
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
	}

	retval = unix_verify_shadow(user);
	if (retval == PAM_AUTHTOK_ERR) {
		if (off(UNIX__IAMROOT)) {
			if (off(UNIX__QUIET))
				pam_error(pamh, "%s", MESSAGE_TOOSOON);
		} else
			retval = PAM_SUCCESS;
	}

out:
#ifdef FAIL_RECORD
	if (retval != PAM_SUCCESS)
		return retval;
#endif

	if (on(UNIX__IAMROOT))
		return retval;

	pam_syslog(pamh, retval == PAM_SUCCESS ? LOG_INFO : LOG_NOTICE,
	    "Authentication %s for %s from %s(uid=%u)"
	    ", for password management",
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
	pam_item_t item;
	char oldprefix[HASH_PREFIX_SIZE];
	/* <DO NOT free() THESE> */
	const char *user, *oldpass, *newpass;
	/* </DO NOT free() THESE> */
	char *newhash;

	D(("called"));

	if (!_set_ctrl(pamh, flags, argc, argv))
		return PAM_ABORT;

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
			return PAM_USER_UNKNOWN;
		}
		if (on(UNIX_AUDIT))
			pam_syslog(pamh, LOG_DEBUG,
			    "Username obtained: %s", user);
	} else {
		pam_syslog(pamh, LOG_ALERT, "Unable to identify user");
		return retval;
	}

	if (!_unix_user_in_db(pamh, user, oldprefix)) {
		pam_syslog(pamh, LOG_NOTICE,
		    "Unable to find user in the selected database");
		return PAM_USER_UNKNOWN;
	}
	if (*oldprefix == '*' && strncmp(oldprefix, "*NP*", 4)) {
		pam_syslog(pamh, LOG_NOTICE,
		    "User \"%s\" does not have a modifiable password", user);
		return PAM_AUTHTOK_ERR;
	}

	if (on(UNIX__PRELIM))
		return unix_prelim(pamh, user);
	if (off(UNIX__UPDATE))
		return PAM_ABORT;

	D(("do update"));

	retval = pam_get_item(pamh, PAM_OLDAUTHTOK, &item);
	if (retval != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_NOTICE, "User not authenticated");
		return retval;
	}

	oldpass = item;
	D(("oldpass=[%s]", oldpass));

	/* check account expiration */
	retval = unix_verify_shadow(user);
	if (retval != PAM_SUCCESS) {
		if (retval == PAM_ACCT_EXPIRED)
			pam_syslog(pamh, LOG_NOTICE, "Account expired");
		return retval;
	}

	D(("get new password now"));

	retval = PAM_AUTHTOK_ERR;
	retry = on(UNIX_USE_FIRST_PASS) ? TRIES - 1 : 0;
	newhash = NULL;
	while (retval != PAM_SUCCESS && retry++ < TRIES) {
		retval = pam_get_authtok(pamh, PAM_AUTHTOK, &newpass, NULL);

		D(("returned to pam_sm_chauthtok"));

		if (retval != PAM_SUCCESS) {
			if (on(UNIX_DEBUG)) {
				pam_syslog(pamh, LOG_ERR,
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

	_pam_overwrite((char *)oldpass);

	if (retval != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_NOTICE, "New password not acceptable");
		_pam_overwrite((char *)newpass);
		return retval;
	}

	/*
	 * By reaching here we have approved the passwords and must now
	 * rebuild the password database file(s).
	 */

	/* First we hash the new password and forget the plaintext. */
	newhash = do_crypt(pamh, newpass);
	_pam_overwrite((char *)newpass);

	D(("password processed"));

	/* update the password database(s) -- race conditions? */
	if (newhash)
		retval = do_setpass(pamh, user, newhash);
	else
		retval = PAM_BUF_ERR;
	_pam_delete(newhash);

	if (retval == PAM_SUCCESS) {
		pam_syslog(pamh, LOG_INFO,
		    "Password for %s changed by %s(uid=%u)",
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
