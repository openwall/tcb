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
#include <pwd.h>
#include <shadow.h>

#include "_tcb.h"

IO_LOOP(read_loop, read,)
IO_LOOP(write_loop, write, const)

#define MAX_DATA_LENGTH			255

#define AUTH_PASSED			TCB_MAGIC
#define AUTH_FAILED			1

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
		if (getuid() != pw->pw_uid)
			return AUTH_FAILED;

		if (!strcmp(pw->pw_passwd, "x")) {
			spw = getspnam(user);
			endspent();
			if (spw)
				stored_hash = strdup(spw->sp_pwdp);
		} else if (!strcmp(pw->pw_passwd, "*NP*")) {
			uid_t old_uid;

			old_uid = geteuid();
			seteuid(pw->pw_uid);
			spw = getspnam(user);
			endspent();
			seteuid(old_uid);

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

	if (!*stored_hash)
		return nullok ? AUTH_PASSED : AUTH_FAILED;

	/* the moment of truth -- do we agree with the password? */
	retval = AUTH_FAILED;
	if (*stored_hash != '*' && *stored_hash != '!') {
		hash = crypt(pass, stored_hash);
		if (hash && !strcmp(hash, stored_hash))
			retval = AUTH_PASSED;
	}

	return retval;
}

static int is_two_strings(char *data, int len)
{
	data[len] = 0;
	return (strlen(data) < len - 1);
}

int main(void)
{
	char option[8];
	char userandpass[MAX_DATA_LENGTH + 1];
	int datalen, nullok, retval;

	openlog("tcb_chkpwd", LOG_CONS | LOG_PID, LOG_AUTH);

	if (isatty(STDIN_FILENO) || isatty(STDOUT_FILENO)) {
		syslog(LOG_NOTICE, "inappropriate use by UID %d", getuid());
		return 1;
	}

	/* read the nullok/nonull option */
	memset(option, 0, sizeof(option));
	if (read_loop(STDIN_FILENO, option, sizeof(option)) <= 0) {
		syslog(LOG_DEBUG, "no option supplied");
		return 1;
	}
	option[sizeof(option) - 1] = '\0';
	nullok = !strcmp(option, "nullok");

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
