#define _GNU_SOURCE
#define _OW_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <rpcsvc/ypclnt.h>

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#if !defined(__LIBPAM_VERSION) && !defined(__LINUX_PAM__)
# include <security/pam_appl.h>
# ifndef PAM_AUTHTOK_RECOVER_ERR
#  define PAM_AUTHTOK_RECOVER_ERR PAM_AUTHTOK_RECOVERY_ERR
# endif
#endif

#include "tcb.h"
#include "_tcb.h"

IO_LOOP(read_loop, read,)
IO_LOOP(write_loop, write, const)

#include "attribute.h"
#include "support.h"

static void data_cleanup(unused pam_handle_t *pamh, void *data,
    unused int error_status)
{
	_pam_delete(data);
}

static int nis_getspnam(struct spwd **spw, const struct passwd *pw)
{
	uid_t old_euid, old_uid;

	D(("called"));

	old_euid = geteuid();
	old_uid = getuid();
	if (old_uid == pw->pw_uid)
		setreuid(old_euid, old_uid);
	else {
		setreuid(0, -1);
		if (setreuid(-1, pw->pw_uid) == -1) {
			setreuid(-1, 0);
			setreuid(0, -1);
			if (setreuid(-1, pw->pw_uid) == -1)
				return -1;
		}
	}

	*spw = getspnam(pw->pw_name);
	endspent();
	if (old_uid == pw->pw_uid)
		setreuid(old_uid, old_euid);
	else {
		if (setreuid(-1, 0) == -1)
			setreuid(old_uid, -1);
		setreuid(-1, old_euid);
	}

	return 0;
}

int unix_getspnam(struct spwd **spw, const struct passwd *pw)
{
	D(("called"));

	if (on(UNIX_NISPLUS) && !strcmp(pw->pw_passwd, "*NP*") &&
	    !nis_getspnam(spw, pw))
		return 0;

	if (on(UNIX_SHADOW)) {
		D(("in non-NIS shadow"));
		*spw = getspnam(pw->pw_name);
		endspent();
		return 0;
	}

	return 1;
}

static char *unix_getsalt(const struct passwd *pw)
{
	struct spwd *spw = NULL;
	char *salt = NULL;
	int is_magic_salt = !strcmp(pw->pw_passwd, "x") ||
	    !strcmp(pw->pw_passwd, "*NP*");

	if (on(UNIX_PASSWD) && !is_magic_salt)
		salt = pw->pw_passwd;

	if (!salt && is_magic_salt && unix_getspnam(&spw, pw) == 0 && spw)
		salt = spw->sp_pwdp;

	return salt ? strdup(salt) : NULL; /* NULL return is fail-close */
}

/* ************************************************************** *
 * Useful non-trivial functions                                   *
 * ************************************************************** */

int _unix_fork(pam_handle_t *pamh, cb_func callback, const void *param)
{
	int retval;
	int pfd[2];
	int status;
	struct sigaction saved_action, action;
	pid_t pid;

	retval = PAM_ABORT;

	action.sa_handler = SIG_DFL;
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_RESTART;

	if (sigaction(SIGCHLD, &action, &saved_action) < 0)
		return retval;

	if (pipe(pfd))
		goto out_signal;

	switch (pid = fork()) {
	case -1:
		close(pfd[0]);
		close(pfd[1]);
		goto out_signal;

	case 0:
		close(pfd[0]);
		D(("auth: in child"));
		retval = callback(pamh, param);
		D(("auth: retval=%d", retval));
		if (write_loop(pfd[1], (char *)&retval, sizeof(retval)) !=
		    sizeof(retval))
			_exit(1);
		_exit(0);

	default:
		close(pfd[1]);
		if (read_loop(pfd[0], (char *)&retval, sizeof(retval)) !=
		    sizeof(retval))
			retval = PAM_ABORT;
		if (waitpid(pid, &status, 0) != pid)
			retval = PAM_ABORT;
		else if (WIFEXITED(status)) {
			if (WEXITSTATUS(status)) {
				pam_syslog(pamh, LOG_CRIT,
				    "Child exited with %d",
				    WEXITSTATUS(status));
				retval = PAM_ABORT;
			}
		} else if (WIFSIGNALED(status)) {
			pam_syslog(pamh, LOG_CRIT, "Child died with signal %d",
			    WTERMSIG(status));
			retval = PAM_ABORT;
		}
		close(pfd[0]);
	}

out_signal:
	sigaction(SIGCHLD, &saved_action, NULL);

	return retval;
}

static int user_in_file(pam_handle_t *pamh, const char *file,
    const char *user, char *hash)
{
	FILE *f;
	int fieldnum = 0, charnum = 0, found = 1, c;
	int namelen = strlen(user);

	f = fopen(file, "r");
	if (!f)
		return 0;

	while ((c = getc(f)) != EOF) {
		if (fieldnum == 0 && charnum < namelen &&
		    c != user[charnum])
			found = 0;
		if (fieldnum == 0 && charnum == namelen && c != ':')
			found = 0;
		if (c == ':') {
			if (fieldnum == 0) {
				if (charnum != namelen || user[charnum])
					found = 0;
				if (found)
					break;
			}
			fieldnum++;
		}
		charnum++;
		if (c == '\n') {
			fieldnum = 0;
			charnum = 0;
			found = 1;
		}
	}
	if (ferror(f))
		pam_syslog(pamh, LOG_CRIT, "Error reading %s: %m", file);
	if (!found) {
		fclose(f);
		return 0;
	}

	for (charnum = 0; charnum < HASH_PREFIX_SIZE - 1; charnum++) {
		c = getc(f);
		if (c == EOF) {
			if (ferror(f)) {
				pam_syslog(pamh, LOG_CRIT,
				    "Error reading %s: %m", file);
				fclose(f);
				return 0;
			}
			break;
		}
		hash[charnum] = c;
	}
	hash[charnum] = 0;

	fclose(f);

	return 1;
}

static int user_in_nisdb(const char *user, char *hash)
{
	char *userinfo = NULL, *domain = NULL, *colon;
	int len, i;

	len = yp_get_default_domain(&domain);
	if (len != YPERR_SUCCESS)
		return 0;

	len = yp_bind(domain);
	if (len != YPERR_SUCCESS)
		return 0;
	i = yp_match(domain, "passwd.byname", user, strlen(user),
	    &userinfo, &len);
	yp_unbind(domain);
	if (i != YPERR_SUCCESS)
		return 0;

	colon = strchr(userinfo, ':');
	if (!colon) {
		free(userinfo);
		return 0;
	}

	*hash = 0;
	strncat(hash, colon + 1, HASH_PREFIX_SIZE - 1);

	free(userinfo);
	return 1;
}

int _unix_user_in_db(pam_handle_t *pamh, const char *user, char *hash)
{
	if (pam_unix_param.write_to == WRITE_NIS)
		return user_in_nisdb(user, hash);

	if (pam_unix_param.write_to == WRITE_PASSWD)
		return user_in_file(pamh, PASSWD_FILE, user, hash);

	if (pam_unix_param.write_to == WRITE_SHADOW) {
		if (!user_in_file(pamh, SHADOW_FILE, user, hash))
			return 0;
		return user_in_file(pamh, PASSWD_FILE, user, hash);
	}

	if (pam_unix_param.write_to == WRITE_TCB) {
		char *tcb_shadow;
		int retval;

		if (tcb_drop_priv(user))
			/* ENOENT, it must be */
			return 0;
		retval = 0;
		if (asprintf(&tcb_shadow, TCB_FMT, user) >= 0) {
			retval = user_in_file(pamh, tcb_shadow, user, hash);
			free(tcb_shadow);
		}
		tcb_gain_priv();
		if (!retval)
			return 0;
		return user_in_file(pamh, PASSWD_FILE, user, hash);
	}

	return 0;
}

static struct passwd fake_pw = {"UNKNOWN USER", "x"};

/*
 * _unix_blankpasswd() is a quick check for a blank password
 *
 * returns TRUE if user does not have a password
 * - to avoid prompting for one in such cases (CG)
 *
 * unix_blankpasswd_plain() returns TCB_MAGIC on success
 */
static int unix_blankpasswd_plain(unused pam_handle_t *pamh,
    const void *void_user)
{
	const char *user = void_user;
	struct passwd *pw;
	char *salt;
	int retval;

	D(("called"));

	if (off(UNIX__NULLOK))
		return -1;

	pw = getpwnam(user);
	endpwent();
	if (!pw) {
		/* we must do getspnam() in order to combat timing attacks */
		salt = unix_getsalt(&fake_pw);
		if (salt)
			_pam_delete(salt);
		return -1;
	}

	salt = unix_getsalt(pw);

	/* Does this user have a password? */
	retval = -1;
	if (salt && !*salt)
		retval = TCB_MAGIC;

	if (salt)
		_pam_delete(salt);

	return retval;
}

int _unix_blankpasswd(pam_handle_t *pamh, const char *user)
{
	D(("called"));

	if (off(UNIX_FORKAUTH))
		return unix_blankpasswd_plain(pamh, user) == TCB_MAGIC;
	else
		return _unix_fork(pamh, unix_blankpasswd_plain,
		    user) == TCB_MAGIC;
}

/*
 * Verify the password of a user.
 */

static int unix_run_helper_binary(const char *user, const char *pass)
{
	int retval = PAM_AUTH_ERR, child, fail = 0, status, fds[2], retpipe[2];
	sighandler_t sigchld, sigpipe;
	int len;
	char *argv[] = {CHKPWD_HELPER, NULL};
	char *envp[] = {NULL};

	D(("called"));

	if (!pam_unix_param.helper)
		return PAM_AUTH_ERR;

	/* create a pipe for the password */
	if (pipe(fds)) {
		D(("could not make pipe"));
		goto out;
	}
	if (pipe(retpipe)) {
		D(("could not make pipe"));
		goto out_pipe;
	}

	sigchld = signal(SIGCHLD, SIG_DFL);
	sigpipe = signal(SIGPIPE, SIG_IGN);

	switch ((child = fork())) {
	case -1:
		D(("fork failed"));
		goto out_signal;

	case 0:
		/* XXX: should really tidy up PAM here too */

		/* reopen stdin as pipe */
		if (close(fds[1]))
			_exit(1);
		if (close(retpipe[0]))
			_exit(1);
		if (dup2(fds[0], STDIN_FILENO) != STDIN_FILENO)
			_exit(1);
		if (dup2(retpipe[1], STDOUT_FILENO) != STDOUT_FILENO)
			_exit(1);

		/* exec binary helper */
		execve(pam_unix_param.helper, argv, envp);

		/* should not get here: exit with error */
		D(("helper binary is not available"));
		_exit(1);

	default:
		/* wait for child */
		close(fds[0]);
		close(retpipe[1]);
		if (on(UNIX__NULLOK)) {
			if (write_loop(fds[1], "nullok\0\0", 8) != 8)
				fail = 1;
		} else {
			if (write_loop(fds[1], "nonull\0\0", 8) != 8)
				fail = 1;
		}
		len = strlen(user) + 1;
		if (write_loop(fds[1], user, len) != len)
			fail = 1;
		else {
			len = strlen(pass) + 1;
			if (write_loop(fds[1], pass, len) != len)
				fail = 1;
		}		
		pass = NULL;
		close(fds[1]);
		/* wait for helper to complete */
		if (waitpid(child, &status, 0) != child) {
			status = 0;
			fail = 1;
		}
		if (read_loop(retpipe[0], (char *)&retval, sizeof(retval)) !=
		    sizeof(retval))
			fail = 1;
		close(retpipe[0]);
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
			fail = 1;
		if (fail)
			retval = PAM_AUTH_ERR;
		else
			retval = (retval == TCB_MAGIC) ?
			    PAM_SUCCESS : PAM_AUTH_ERR;
	}

out_signal:
	close(retpipe[0]);
	close(retpipe[1]);
	signal(SIGPIPE, sigpipe);
	signal(SIGCHLD, sigchld);

out_pipe:
	close(fds[0]);
	close(fds[1]);

out:
	D(("returning %d", retval));
	return retval;
}

static int check_crypt(pam_handle_t *pamh, const char *pass,
    const char *stored_hash)
{
	const char *salt;
	char *hash, *fake_salt;
	char input[16];
	int retval;

	if (!*stored_hash && on(UNIX__NULLOK)) {
		D(("user has empty password - access granted"));
		return PAM_SUCCESS;
	}

	/* This exists because of timing attacks. */
	memset(input, 0x55, sizeof(input));
	fake_salt = crypt_gensalt_ra(pam_unix_param.crypt_prefix,
	    pam_unix_param.count, input, sizeof(input));

	if (!fake_salt) {
		pam_syslog(pamh, LOG_CRIT, "crypt_gensalt_ra: %m");
		return PAM_BUF_ERR;
	}

	salt = stored_hash;
	if (*salt == '\0' || *salt == '*' || *salt == '!')
		salt = fake_salt;

	hash = crypt_wrapper(pamh, pass, salt);
	pass = NULL; /* no longer needed here */

	/* the moment of truth -- do we agree with the password? */
	D(("comparing state of hash[%s] and stored_hash[%s]",
	    hash, stored_hash));
	if (!hash)
		retval = PAM_BUF_ERR;
	else if (strcmp(hash, stored_hash) == 0 && salt != fake_salt)
		retval = PAM_SUCCESS;
	else
		retval = PAM_AUTH_ERR;

	if (hash)
		_pam_delete(hash);
	if (fake_salt)
		_pam_delete(fake_salt);

	return retval;
}

static int unix_verify_password_plain(pam_handle_t *pamh,
    const void *void_arg)
{
	const struct unix_verify_password_param *arg = void_arg;
	const char *user = arg->user;
	const char *pass = arg->pass;
	struct passwd *pw;
	char *salt;
	int faking, retval;

	D(("called"));

	/* locate the entry for this user */
	D(("locating user's record"));

	pw = getpwnam(user);
	endpwent();
	if (!pw) {
		/* This exists because of timing attacks. */
		faking = 1;
		pw = &fake_pw;
		salt = unix_getsalt(pw);
		if (salt)
			_pam_delete(salt);
		salt = strdup("*");
		if (!salt) {
			retval = PAM_BUF_ERR;
			goto out;
		}
	} else {
		faking = 0;
		salt = unix_getsalt(pw);
	}

	retval = PAM_SUCCESS;
	if (!pass)
		pass = "";
	if (!salt) {
		/* we're not faking, we have an existing user, so... */
		uid_t uid = getuid();
		if (uid == geteuid() && uid == pw->pw_uid && uid != 0) {
			/* We are not root perhaps this is the reason? */
			D(("running helper binary"));
			retval = unix_run_helper_binary(user, pass);
		} else {
			D(("user's record unavailable"));
			pam_syslog(pamh, LOG_ALERT,
			    "Credentials for user %s unknown", user);
			pass = NULL;
			retval = PAM_AUTHINFO_UNAVAIL;
		}
	} else
		retval = check_crypt(pamh, pass, salt);

	if (faking)
		retval = PAM_AUTHINFO_UNAVAIL;

	if (salt)
		_pam_delete(salt);

out:
	D(("done [%d]", retval));
	return retval + TCB_MAGIC;
}

#ifdef FAIL_RECORD
/*
 * The following is used to keep track of the number of times a user fails
 * to authenticate themselves.
 */
#define DATA_FAIL_PREFIX		"-UN*X-FAIL-"
#define TRIES				3

struct failed_auth {
	char *user;		/* user that's failed to be authenticated */
	char *name;		/* attempt from user with name */
	uid_t id;		/* uid of name'd user */
	int count;		/* number of failures so far */
};

#ifndef PAM_DATA_REPLACE
#error "Need Linux-PAM 0.52 or better"
#endif

static void failures_cleanup(pam_handle_t *pamh, void *data, int error_status)
{
	struct failed_auth *failures;
	int quiet;

	D(("called"));

	failures = (struct failed_auth *)data;
	quiet = error_status & PAM_DATA_SILENT; /* should we log something? */
	error_status &= PAM_DATA_REPLACE; /* are we just replacing data? */

	if (failures) {
		if (!quiet && !error_status) {
			/* log the number of authentication failures */
			if (failures->count > 1) {
				pam_syslog(pamh, LOG_NOTICE,
				    "%d more authentication failure%s "
				    "for %s from %s(uid=%u)",
				    failures->count - 1,
				    failures->count == 2 ? "" : "s",
				    failures->user,
				    failures->name, failures->id);
			}
		}
		_pam_delete(failures->user);
		_pam_delete(failures->name);
		free(failures);
	}
}

static int do_record_failure(pam_handle_t *pamh, const char *user, int retval)
{
	char *data_name;

	if (asprintf(&data_name, "%s%s", DATA_FAIL_PREFIX, user) < 0) {
		pam_syslog(pamh, LOG_CRIT, "Out of memory");
		return PAM_BUF_ERR;
	}

	if (retval == PAM_SUCCESS) {
		/* reset failures */
		pam_set_data(pamh, data_name, NULL, failures_cleanup);
	} else {
		struct failed_auth *new;

		/* get a failure recorder */
		new = (struct failed_auth *)malloc(sizeof(struct failed_auth));

		if (new) {
			pam_data_t item;
			const struct failed_auth *old;

			/* possible strdup() failures; nothing we can do;
			 * incomplete logging in this case */
			new->user = strdup(getpwnam(user) ?
			    user : "UNKNOWN USER");
			new->id = getuid();
			new->name = strdup(getlogin() ?: "");

			/* any previous failures for this user? */
			if (pam_get_data(pamh, data_name, &item)
			    != PAM_SUCCESS)
				item = NULL;
			old = item;

			if (old) {
				new->count = old->count + 1;
				if (new->count >= TRIES)
					retval = PAM_MAXTRIES;
			} else {
				pam_syslog(pamh, LOG_NOTICE,
				    "Authentication failed "
				    "for %s from %s(uid=%u)",
				    new->user, new->name, new->id);
				new->count = 1;
			}
			pam_set_data(pamh, data_name, new, failures_cleanup);
		} else {
			pam_syslog(pamh, LOG_CRIT,
			    "No memory for failure recorder");
			retval = PAM_BUF_ERR;
		}
	}

	if (data_name)
		_pam_delete(data_name);
	return retval;
}
#endif

int _unix_verify_password(pam_handle_t *pamh,
    const char *user, const char *pass)
{
	struct unix_verify_password_param arg = {pamh, user, pass};
	int retval;

#ifdef HAVE_PAM_FAIL_DELAY
	if (off(UNIX_NODELAY)) {
		D(("setting delay"));
		/* 2 sec delay for on failure */
		(void) pam_fail_delay(pamh, 2000000);
	}
#endif

	if (off(UNIX_FORKAUTH))
		retval = unix_verify_password_plain(pamh, &arg) - TCB_MAGIC;
	else
		retval = _unix_fork(pamh, unix_verify_password_plain,
		    &arg) - TCB_MAGIC;
#ifdef FAIL_RECORD
	retval = do_record_failure(pamh, user, retval);
#endif
	return retval;
}

/*
 * Obtain a password from the user.
 */

int _unix_read_password(pam_handle_t *pamh,
    const char *comment, const char *prompt1, const char *prompt2,
    const char *data_name, const char **pass)
{
	pam_item_t item;
	char *token;
	int authtok_flag;
	int retval = PAM_SUCCESS;

	D(("called"));

	/* make sure nothing inappropriate gets returned */
	*pass = token = NULL;

	/* which authentication token are we getting? */
	authtok_flag = on(UNIX__OLD_PASSWD) ? PAM_OLDAUTHTOK : PAM_AUTHTOK;

	/* should we obtain the password from a PAM item? */
	if (pam_unix_param.authtok_usage != USE_NONE) {
		retval = pam_get_item(pamh, authtok_flag, &item);
		if (retval != PAM_SUCCESS) {
			/* very strange */
			return retval;
		} else if (item) { /* we have a password! */
			*pass = item;
			item = NULL;
			return PAM_SUCCESS;
		} else if (pam_unix_param.authtok_usage == USE_FORCED) {
			return PAM_AUTHTOK_RECOVER_ERR; /* didn't work */
		} else if (on(UNIX_USE_AUTHTOK)
		    && off(UNIX__OLD_PASSWD)) {
			return PAM_AUTHTOK_RECOVER_ERR;
		}
	}

	/* getting here implies we will have to get the password from the
	 * user directly */
	if (comment && off(UNIX__QUIET)) {
		retval = pam_info(pamh, "%s", comment);
	}

	if (retval == PAM_SUCCESS && prompt1) {
		retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &token, "%s",
		    prompt1);
	}

	if (retval == PAM_SUCCESS && token && prompt2) {
		char *resp;
		retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &resp, "%s",
		    prompt2);
		if (retval != PAM_SUCCESS || !resp) {
			_pam_delete(token);
		} else if (strcmp(token, resp)) {
			_pam_delete(token);
			pam_error(pamh, "%s", MESSAGE_MISTYPED);
			retval = PAM_AUTHTOK_RECOVER_ERR;
		}
		_pam_delete(resp);
	}

	if (retval != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_NOTICE,
		    "Unable to obtain a password");
		return retval;
	}

	/* 'token' is the entered password */
	if (off(UNIX_NOT_SET_PASS)) {
		/* we store this password as an item */
		retval = pam_set_item(pamh, authtok_flag, token);
		_pam_delete(token);
		if (retval != PAM_SUCCESS ||
		    (retval = pam_get_item(pamh, authtok_flag, &item))
		    != PAM_SUCCESS) {
			pam_syslog(pamh, LOG_CRIT,
			    "Error manipulating password");
			return retval;
		}
	} else {
		/*
		 * Then store it as data specific to this module. pam_end()
		 * will arrange to clean it up.
		 */
		retval = pam_set_data(pamh, data_name, (void *)token,
		    data_cleanup);
		if (retval != PAM_SUCCESS) {
			_pam_delete(token);
			pam_syslog(pamh, LOG_CRIT,
			    "Error manipulating password");
			return retval;
		}
		item = token;
	}

	*pass = item;

	return PAM_SUCCESS;
}

static char *crypt_wrapper_ra(pam_handle_t *pamh, const char *key,
    const char *salt)
{
	char *retval;
	void *data = NULL;
	int size = 0;

	retval = crypt_ra(key, salt, &data, &size);
	if (retval)
		retval = strdup(retval); /* we return NULL if strdup fails */
	else
		pam_syslog(pamh, LOG_CRIT, "crypt_ra: %m");
	if (data) {
		memset(data, 0, size);
		free(data);
	}
	return retval;
}

char *crypt_wrapper(pam_handle_t *pamh, const char *key,
    const char *salt)
{
	char *retval;

	if (off(UNIX_PLAIN_CRYPT))
		return crypt_wrapper_ra(pamh, key, salt);

	errno = 0;
	retval = crypt(key, salt);
	if (!retval || strlen(retval) < 13) {
		pam_syslog(pamh, LOG_CRIT, "crypt: %s",
		    errno ? strerror(errno) : "Failed");
		return NULL;
	}

	return strdup(retval); /* we return NULL if strdup fails */
}

char *do_crypt(pam_handle_t *pamh, const char *pass)
{
	char *retval;
	char *salt;
	char entropy[16];
	int fd;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		pam_syslog(pamh, LOG_CRIT, "open urandom: %m");
		return NULL;
	}
	if (read_loop(fd, entropy, sizeof(entropy)) != sizeof(entropy)) {
		pam_syslog(pamh, LOG_CRIT, "read urandom: %m");
		close(fd);
		return NULL;
	}
	close(fd);

	salt = crypt_gensalt_ra(pam_unix_param.crypt_prefix,
	    pam_unix_param.count, entropy, sizeof(entropy));

	memset(entropy, 0, sizeof(entropy));

	if (!salt) {
		pam_syslog(pamh, LOG_CRIT, "crypt_gensalt_ra: %m");
		return NULL;
	}

	retval = crypt_wrapper(pamh, pass, salt);

	_pam_delete(salt);

	return retval;
}

struct pam_unix_params pam_unix_param;

static struct bool_names {
	const char *name;
	int optval, negate;
} unix_bools[] = {
	{"audit", UNIX_AUDIT, 0},
	{"not_set_pass", UNIX_NOT_SET_PASS, 0},
	{"use_authtok", UNIX_USE_AUTHTOK, 0},
	{"shadow", UNIX_SHADOW, 0},
	{"nisplus", UNIX_NISPLUS, 0},
	{"passwd", UNIX_PASSWD, 0},
	{"openlog", UNIX_OPENLOG, 0},
	{"noopenlog", UNIX_OPENLOG, 1},
	{"nullok", UNIX__NULLOK, 0},
	{"debug", UNIX_DEBUG, 0},
	{"nodelay", UNIX_NODELAY, 0},
	{"plain_crypt", UNIX_PLAIN_CRYPT, 0},
	{"fork", UNIX_FORKAUTH, 0},
	{"likeauth", UNIX_LIKE_AUTH, 0},
	{"nolog", UNIX_NOLOG, 0},
	{"blank_nolog", UNIX_NOLOG_BLANK, 0},
	{NULL, 0, 0}
};

static int parse_opt(pam_handle_t *pamh, const char *item,
    struct cmdline_opts *parsed)
{
	const char *opt, *optname;
	int j;

	if (!strcmp(item, "md5"))
		opt = "prefix=$1$";
	else if (!strcmp(item, "try_first_pass"))
		opt = "authtok_usage=try";
	else if (!strcmp(item, "use_first_pass"))
		opt = "authtok_usage=forced";
	else
		opt = item;

	D(("pam_unix arg: %s", item));
	for (j = 0; unix_bools[j].name; ++j)
	if (!strcmp(opt, unix_bools[j].name)) {
		if (unix_bools[j].negate)
			unset(unix_bools[j].optval);
		else
			set(unix_bools[j].optval);
		return 1;
	}

	for (j = 0; (optname = parsed[j].optname); j++)
	if (!strncmp(optname, opt, strlen(optname))) {
		const char *prev = parsed[j].value;
		if (prev && strcmp(prev, opt)) {
			pam_syslog(pamh, LOG_ERR, "Conflicting options "
			    "\"%s\" and \"%s\"", parsed[j].orig, item);
			return 0;
		}
		parsed[j].value = opt;
		parsed[j].orig = item;
		return 1;
	}

	pam_syslog(pamh, LOG_ERR, "Unrecognized option: %s", item);
	return 0;
}

static const char *get_optval(const char *name, struct cmdline_opts *parsed)
{
	int i;
	const char *optname, *optval;

	for (i = 0; (optname = parsed[i].optname); i++)
	if (!strcmp(optname, name)) {
		if (parsed[i].value) {
			optval = strchr(parsed[i].value, '=');
			return optval ? optval + 1 : NULL;
		}
		return NULL;
	}

	return NULL;
}

int _set_ctrl(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	unsigned int i;
	const char *param;
	struct cmdline_opts the_cmdline_opts[] = {
		{"authtok_usage=", NULL, NULL},
		{"helper=", NULL, NULL},
		{"count=", NULL, NULL},
		{"write_to=", NULL, NULL},
		{"prefix=", NULL, NULL},
		{NULL, NULL, NULL}
	};

	D(("called"));

	for (i = 0; i < OPT_SIZE; i++)
		pam_unix_param.ctrl[i] = 0;

#ifdef ENABLE_OPENLOG
	set(UNIX_OPENLOG);
#endif

	/* set some flags manually */
	if (getuid() == 0 && !(flags & PAM_CHANGE_EXPIRED_AUTHTOK)) {
		D(("IAMROOT"));
		set(UNIX__IAMROOT);
	}
	if (flags & PAM_UPDATE_AUTHTOK) {
		D(("UPDATE_AUTHTOK"));
		set(UNIX__UPDATE);
	}
	if (flags & PAM_PRELIM_CHECK) {
		D(("PRELIM_CHECK"));
		set(UNIX__PRELIM);
	}
	if (flags & PAM_SILENT) {
		D(("SILENT"));
		set(UNIX__QUIET);
	}

	/* now parse the arguments to this module */
	for (; argc > 0; argc--, argv++)
		if (!parse_opt(pamh, *argv, the_cmdline_opts))
			return 0;
	param = get_optval("prefix=", the_cmdline_opts);
	pam_unix_param.crypt_prefix = param ?: "$2a$";

	param = get_optval("helper=", the_cmdline_opts);
	pam_unix_param.helper = param ?: CHKPWD_HELPER;

	param = get_optval("count=", the_cmdline_opts);
	if (param) {
		char *end;
		/*
		 * SUSv2 says:
		 * Because 0 and ULONG_MAX are returned on error and
		 * are also valid returns on success, an application
		 * wishing to check for error situations should set
		 * errno to 0, then call strtoul(), then check errno.
		 */
		errno = 0;
		pam_unix_param.count = strtoul(param, &end, 10);
		if (errno || !*param || *end) {
			pam_syslog(pamh, LOG_ERR,
			    "Invalid count= argument: %s", param);
			return 0;
		}
	} else
		pam_unix_param.count = 0;

	param = get_optval("authtok_usage=", the_cmdline_opts);
	if (param) {
		if (!strcmp(param, "no"))
			pam_unix_param.authtok_usage = USE_NONE;
		else if (!strcmp(param, "try"))
			pam_unix_param.authtok_usage = USE_TRY;
		else if (!strcmp(param, "forced"))
			pam_unix_param.authtok_usage = USE_FORCED;
		else {
			pam_syslog(pamh, LOG_ERR,
			    "Invalid authtok_usage= argument: %s", param);
			return 0;
		}
	} else
		pam_unix_param.authtok_usage = USE_NONE;

	param = get_optval("write_to=", the_cmdline_opts);
	if (param) {
		if (!strcmp(param, "passwd"))
			pam_unix_param.write_to = WRITE_PASSWD;
		else if (!strcmp(param, "shadow"))
			pam_unix_param.write_to = WRITE_SHADOW;
		else if (!strcmp(param, "tcb"))
			pam_unix_param.write_to = WRITE_TCB;
		else if (!strcmp(param, "nis"))
			pam_unix_param.write_to = WRITE_NIS;
		else {
			pam_syslog(pamh, LOG_ERR,
			    "Invalid write_to argument: %s", param);
			return 0;
		}
	} else
		pam_unix_param.write_to = WRITE_SHADOW;

	/* auditing is a more sensitive version of debug */
	if (on(UNIX_AUDIT))
		set(UNIX_DEBUG);

	D(("done"));
	return 1;
}
