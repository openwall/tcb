/*
 * This program is designed to run with sufficient privilege to read
 * the password hash for the current user. It provides a mechanism for
 * the user to verify their own password.
 *
 * The password is read from the standard input. The output of this
 * program indicates whether the user is authenticated or not.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <pwd.h>
#include <shadow.h>

#include "_tcb.h"

IO_LOOP(read_loop, read,)
IO_LOOP(write_loop, write, const)

#define MAX_DATA_LENGTH			255

#define AUTH_PASSED			TCB_MAGIC
#define AUTH_FAILED			1

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

static void zeroise(char *str)
{
	while (*str)
		*(str++) = '\0';
}

static int unix_getspnam(struct spwd **spw, const struct passwd *pw, int shadow)
{
	if (shadow) {
		*spw = getspnam(pw->pw_name);
		endspent();
		return 0;
	}

	return 1;
}

static int acct_shadow(const void *void_user, int shadow)
{
	int daysleft;
	time_t curdays;
	const char *user = void_user;
	struct passwd *pw;
	struct spwd *spw = NULL;

	pw = getpwnam(user);
	endpwent();
	if (pw) {
		uid_t uid = getuid();
		if (uid != pw->pw_uid && uid != 0)
			return ACCT_1;
	}
	if (!pw)
		return ACCT_1; /* shouldn't happen */
	if (!shadow && strcmp(pw->pw_passwd, "x")
	    && strcmp(pw->pw_passwd, "*NP*"))
		return ACCT_SUCCESS;

	if (unix_getspnam(&spw, pw, shadow))
		return ACCT_1;

	if (!spw)
		return ACCT_2;

	curdays = time(NULL) / (60 * 60 * 24);
	syslog(LOG_DEBUG, "today is %ld, last change %ld",
		curdays, spw->sp_lstchg);
	if ((curdays > spw->sp_expire) && (spw->sp_expire != -1))
		return ACCT_3;

	if ((curdays > (spw->sp_lstchg + spw->sp_max + spw->sp_inact)) &&
	    (spw->sp_max != -1) && (spw->sp_inact != -1) &&
	    (spw->sp_lstchg != 0))
		return ACCT_4;

	syslog(LOG_DEBUG, "when was the last change");
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

static int unix_verify_password(const char *user, const char *pass, int nullok)
{
	struct passwd *pw;
	struct spwd *spw;
	char *stored_hash, *hash;
	int retval;

	pw = getpwnam(user);
	endpwent();

	stored_hash = NULL;
	if (pw) {
		uid_t uid = getuid();
		if (uid != pw->pw_uid && uid != 0)
			return AUTH_FAILED;

		if (!strcmp(pw->pw_passwd, "x")) {
			spw = getspnam(user);
			endspent();
			if (spw)
				stored_hash = strdup(spw->sp_pwdp);
		} else {
			/* strdup can fail, it's fail-close */
			stored_hash = strdup(pw->pw_passwd);
		}
	}

	if (!stored_hash) {
		syslog(LOG_ALERT, "user unknown");
		return AUTH_FAILED;
	}

	if (!*stored_hash) {
		free(stored_hash);
		return nullok ? AUTH_PASSED : AUTH_FAILED;
	}

	/* the moment of truth -- do we agree with the password? */
	retval = AUTH_FAILED;
	if (*stored_hash != '*' && *stored_hash != '!') {
		hash = crypt(pass, stored_hash);
		if (hash && !strcmp(hash, stored_hash)) {
			retval = AUTH_PASSED;
			zeroise(hash);
		}
	}

	zeroise(stored_hash);
	free(stored_hash);
	return retval;
}

static int is_two_strings(char *data, unsigned int len)
{
	data[len] = 0;
	return (1 + strlen(data) < len);
}

static int acctverify(int shadow)
{
	int datalen, retval;
	char username[MAX_DATA_LENGTH + 1];

	retval = ACCT_0;

	/* read the user from stdin (a pipe from the PAM module) */
	datalen = read_loop(STDIN_FILENO, username, MAX_DATA_LENGTH);
	if (datalen < 0)
		syslog(LOG_DEBUG, "no username supplied");
	else if (datalen >= MAX_DATA_LENGTH)
		syslog(LOG_DEBUG, "username too long");
	else
		retval = acct_shadow(username, shadow);

	memset(username, 0, sizeof(username));

	/* return pass or fail */
	if (write_loop(STDOUT_FILENO, (char *)&retval, sizeof(retval)) ==
	    sizeof(retval))
		return retval == ACCT_SUCCESS ? 0 : 1;
	else
		return 1;
}

static int passverify(int nullok)
{
	int datalen, retval;
	char userandpass[MAX_DATA_LENGTH + 1];

	retval = AUTH_FAILED;

	/* read the user/password from stdin (a pipe from the PAM module) */
	datalen = read_loop(STDIN_FILENO, userandpass, MAX_DATA_LENGTH);
	if (datalen < 0)
		syslog(LOG_DEBUG, "no user/password supplied");
	else if (datalen >= MAX_DATA_LENGTH)
		syslog(LOG_DEBUG, "user/password too long");
	else if (!is_two_strings(userandpass, datalen))
		syslog(LOG_DEBUG, "malformed data from parent");
	else
		retval = unix_verify_password(userandpass,
			userandpass + strlen(userandpass) + 1, nullok);

	memset(userandpass, 0, sizeof(userandpass));

	/* return pass or fail */
	if (write_loop(STDOUT_FILENO, (char *)&retval, sizeof(retval)) ==
	    sizeof(retval))
		return retval == AUTH_PASSED ? 0 : 1;
	else
		return 1;
}

int main(int argc, char* argv[])
{
	char option[8];
	int flag, retval = 1;

	openlog("tcb_chkpwd", LOG_CONS | LOG_PID, LOG_AUTH);

	if (argc != 2 || isatty(STDIN_FILENO) || isatty(STDOUT_FILENO)) {
		syslog(LOG_NOTICE, "inappropriate use by UID %d", getuid());
		goto out;
	}

	/* read the applicable option from pipe */
	memset(option, 0, sizeof(option));
	if (read_loop(STDIN_FILENO, option, sizeof(option)) <= 0) {
		syslog(LOG_DEBUG, "no option supplied");
		goto out;
	}
	option[sizeof(option) - 1] = '\0';

	if (!strcmp(argv[1], "chkacct")) {
		flag = !strcmp(option, "shadow");
		retval = acctverify(flag);
		goto out;
	}

	if (!strcmp(argv[1], "chkpwd")) {
		flag = !strcmp(option, "nullok");
		retval = passverify(flag);
	}

out:
	return retval;
}
