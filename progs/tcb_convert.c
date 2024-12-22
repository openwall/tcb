#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "tcb.h"

#define LINE_BUFFER_SIZE		1024
#define USERNAME_SIZE			LINE_BUFFER_SIZE

#define DEFS_FILE			"/etc/login.defs"
#define DEFS_TCB_AUTH_GROUP		"TCB_AUTH_GROUP"

static gid_t authgid;
static int dirmode, spwmode;

/* XXX: the shadow suite should export getdef*() in a shared library */
static int tcb_auth_is_set(void)
{
	FILE *f;
	char linebuf[LINE_BUFFER_SIZE];
	char *p, *q;
	int retval;

	f = fopen(DEFS_FILE, "r");
	if (!f) {
		perror("open: " DEFS_FILE);
		return -1;
	}

	retval = 0;
	while (fgets(linebuf, sizeof(linebuf), f)) {
		if (!strchr(linebuf, '\n')) {
			fprintf(stderr, "Line too long in " DEFS_FILE "\n");
			retval = -1;
			break;
		}
		if (linebuf[0] == '#')
			continue;
		p = linebuf;
		while (*p == ' ' || *p == '\t')
			p++;
		if (strncmp(p, DEFS_TCB_AUTH_GROUP,
		    strlen(DEFS_TCB_AUTH_GROUP)))
			continue;
		p += strlen(DEFS_TCB_AUTH_GROUP);
		if (!(*p == ' ' || *p == '\t'))
			continue;
		while (*p == ' ' || *p == '\t')
			p++;
		q = p + strlen(p) - 1;
		if (*q != '\n')
			continue;
		*q-- = '\0';
		while (q >= p && (*q == ' ' || *q == '\t'))
			*q-- = '\0';
		if (!strcmp(p, "yes"))
			retval = 1;
		else if (!strcmp(p, "no"))
			retval = 0;
		else {
			fprintf(stderr, "Invalid " DEFS_TCB_AUTH_GROUP
			    " setting in " DEFS_FILE "\n");
			retval = -1;
			break;
		}
	}
	if (ferror(f))
		retval = -1;

	if (fclose(f))
		retval = -1;

	return retval;
}

static int copy_user_to_tcb(const char *user, char *linebuf, FILE *inf)
{
	FILE *outf;
	struct passwd *pw;
	char *tcbname;
	int retval;

	retval = -1;

	pw = getpwnam(user);
	if (!pw) {
		fprintf(stderr, "getpwnam: User %s not found\n", user);
		goto out;
	}

	if (asprintf(&tcbname, "%s/%s", TCB_DIR, user) < 0) {
		perror("asprintf");
		goto out;
	}

	if (mkdir(tcbname, 0)) {
		perror("mkdir");
		goto out_free;
	}

	if (chown(tcbname, pw->pw_uid, authgid)) {
		perror("chown");
		goto out_free;
	}
	if (chmod(tcbname, dirmode)) {
		perror("chmod");
		goto out_free;
	}

	free(tcbname);
	if (asprintf(&tcbname, TCB_FMT, user) < 0) {
		perror("asprintf");
		goto out;
	}

	/* This assumes that TCB_DIR isn't accessible to the users yet */
	outf = fopen(tcbname, "w");
	if (!outf) {
		perror("fopen");
		goto out_free;
	}

	do {
		if (fwrite(linebuf, strlen(linebuf), 1, outf) != 1) {
			perror("fwrite");
			goto out_close;
		}
		if (strchr(linebuf, '\n'))
			break;
	} while (fgets(linebuf, sizeof(linebuf), inf));
	if (ferror(inf)) {
		perror("fgets");
		goto out_close;
	}

	if (fclose(outf)) {
		perror("fclose");
		goto out_free;
	}

	if (chown(tcbname, pw->pw_uid, authgid)) {
		perror("chown");
		goto out_free;
	}
	if (chmod(tcbname, spwmode)) {
		perror("chmod");
		goto out_free;
	}

	retval = 0;
	goto out_free;

out_close:
	if (fclose(outf))
		perror("fclose");

out_free:
	free(tcbname);

out:
	return retval;
}

static int copy_to_tcb(void)
{
	char linebuf[LINE_BUFFER_SIZE];
	char user[USERNAME_SIZE];
	struct group *gr;
	gid_t shadowgid;
	FILE *inf;
	char *in, *out;

	gr = getgrnam("shadow");
	if (!gr) {
		fprintf(stderr, "\"shadow\" group not found.\n");
		return -1;
	}
	shadowgid = gr->gr_gid;

	switch (tcb_auth_is_set()) {
	case 1:
		gr = getgrnam("auth");
		if (!gr) {
			fprintf(stderr, DEFS_TCB_AUTH_GROUP " is set but "
			    "\"auth\" group not found.\n");
			return -1;
		}
		authgid = gr->gr_gid;
		dirmode = 02710;
		spwmode = 0640;
		break;

	case 0:
		authgid = shadowgid;
		dirmode = 02700;
		spwmode = 0600;
		break;

	default:
		return -1;
	}

	if (mkdir(TCB_DIR, 0)) {
		if (errno == EEXIST)
			fprintf(stderr, TCB_DIR " exists, remove it first.\n");
		else
			perror("mkdir: " TCB_DIR);
		return -1;
	}

	inf = fopen("/etc/shadow", "r");
	if (!inf) {
		perror("fopen: /etc/shadow");
		return -1;
	}

	while (fgets(linebuf, sizeof(linebuf), inf)) {
		in = linebuf;
		out = user;
		while (*in && *in != ':' && out < &user[sizeof(user) - 1])
			*out++ = *in++;
		if (*in != ':') {
			fprintf(stderr, "Suspicious /etc/shadow line "
			    "starting with '%s', aborting.\n", linebuf);
			fclose(inf);
			return -1;
		}
		*out = '\0';
		if (copy_user_to_tcb(user, linebuf, inf)) {
			fclose(inf);
			return -1;
		}
	}
	if (ferror(inf)) {
		perror("fgets");
		return -1;
	}

	if (fclose(inf)) {
		perror("fclose");
		return -1;
	}

	if (chown(TCB_DIR, 0, shadowgid)) {
		perror("chown: " TCB_DIR);
		return -1;
	}
	if (chmod(TCB_DIR, 0710)) {
		perror("chmod: " TCB_DIR);
		return -1;
	}

	return 0;
}

int main(void)
{
	int status;

	if (getuid() || geteuid()) {
		fprintf(stderr, "Only root can do this!\n");
		return 1;
	}

	if (lckpwdf()) {
		perror("lckpwdf");
		return 1;
	}

	status = copy_to_tcb();

	ulckpwdf();

	return status ? 1 : 0;
}
