#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <grp.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "tcb.h"

#define SHADOW_FILE			"/etc/shadow"
#define SHADOW_TMP_FILE			SHADOW_FILE ".tmp"

#define XPUTC(c, outf) \
	if (putc((c), (outf)) == EOF) { \
		perror("putc"); \
		goto out_close; \
	}

static int copy_user_from_tcb(const char *user, FILE *outf)
{
	FILE *inf;
	char *tcbname;
	int fd;
	unsigned char *p;
	int c, colons;
	char *msg;
	int retval;

	retval = -1;

	asprintf(&tcbname, TCB_FMT, user);
	if (!tcbname) {
		perror("asprintf");
		goto out;
	}

	if (tcb_drop_priv(user)) {
		perror("tcb_drop_priv");
		goto out_free;
	}
	fd = open(tcbname, O_RDONLY | O_NOCTTY | O_NONBLOCK | O_NOFOLLOW);
	if (fd < 0) {
		perror("open");
		tcb_gain_priv();
		goto out_free;
	}
	tcb_gain_priv();
	if (tcb_is_suspect(fd)) {
		fprintf(stderr, "%s is not a regular file or is sparse.\n",
		    tcbname);
		close(fd);
		goto out_free;
	}
	inf = fdopen(fd, "r");
	if (!inf) {
		perror("fdopen");
		close(fd);
		goto out_free;
	}

	for (p = (unsigned char *)user; *p; p++) {
		c = getc(inf);
		if (c != *p) {
			msg = "No or wrong username";
			goto out_msg;
		}
		XPUTC(c, outf);
	}
	c = getc(inf);
	if (c != ':') {
		msg = "No or wrong username";
		goto out_msg;
	}
	XPUTC(c, outf);
	colons = 1;
	while (1) {
		c = getc(inf);
		if (c == EOF) {
			msg = "No newline character";
			goto out_msg;
		}
		XPUTC(c, outf);
		if (c == '\n')
			break;
		if (c == ':')
			colons++;
	}
	c = getc(inf);
	if (c != EOF) {
		msg = "Extra data after newline";
		goto out_msg;
	}
	if (colons != 8) {
		msg = "Wrong number of fields";
		goto out_msg;
	}

	retval = 0;
	goto out_close;

out_msg:
	fprintf(stderr, "%s is corrupt: %s\n", tcbname, msg);

out_close:
	if (fclose(inf)) {
		perror("fclose");
		retval = -1;
	}

out_free:
	free(tcbname);

out:
	return retval;
}

#undef XPUTC

static int copy_from_tcb(void)
{
	DIR *tcbdir;
	struct dirent *entry;
	FILE *outf;
	int fd;
	struct group *gr;
	gid_t shadowgid;
	int retval;

	retval = -1;

	gr = getgrnam("shadow");
	if (!gr) {
		fprintf(stderr, "\"shadow\" group not found.\n");
		goto out;
	}
	shadowgid = gr->gr_gid;

	tcbdir = opendir(TCB_DIR);
	if (!tcbdir) {
		perror("opendir: " TCB_DIR);
		goto out;
	}

	fd = open(SHADOW_TMP_FILE, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR);
	if (fd < 0) {
		perror("open: " SHADOW_TMP_FILE);
		goto out_closedir;
	}
	outf = fdopen(fd, "w");
	if (!outf) {
		perror("fdopen");
		close(fd);
		goto out_unlink;
	}

	/*
	 * SUSv2 says:
	 * Applications wishing to check for error situations should set
	 * errno to 0 before calling readdir().  If errno is set to non-zero
	 * on return, an error occurred.
	 */
	errno = 0;
	while ((entry = readdir(tcbdir))) {
		if (!strcmp(entry->d_name, ".") ||
		    !strcmp(entry->d_name, ".."))
			continue;
		if (copy_user_from_tcb(entry->d_name, outf))
			goto out_fclose;
	}
	if (errno) {
		perror("readdir");
		goto out_fclose;
	}

	if (fclose(outf)) {
		perror("fclose");
		goto out_unlink;
	}

	if (chown(SHADOW_TMP_FILE, 0, shadowgid)) {
		perror("chown");
		goto out_unlink;
	}
	if (chmod(SHADOW_TMP_FILE, S_IRUSR | S_IRGRP)) {
		perror("chmod");
		goto out_unlink;
	}

	if (rename(SHADOW_TMP_FILE, SHADOW_FILE)) {
		perror("rename");
		goto out_unlink;
	}

	retval = 0;
	goto out_closedir;

out_fclose:
	if (fclose(outf))
		perror("fclose");

out_unlink:
	if (unlink(SHADOW_TMP_FILE))
		perror("unlink");

out_closedir:
	if (closedir(tcbdir)) {
		perror("closedir");
		retval = -1;
	}

out:
	return retval;
}

int main(void)
{
	struct stat st;
	struct group *gr;
	gid_t sysgid;
	int status;

	gr = getgrnam("sys");
	if (!gr) {
		fprintf(stderr, "\"sys\" group not found.\n");
		return 1;
	}
	sysgid = gr->gr_gid;

	if (stat(TCB_DIR, &st)) {
		perror("stat: " TCB_DIR);
		return 1;
	}

	/* XXX: this makes group "sys" special during the unconversion */
	if (chown(TCB_DIR, 0, sysgid)) {
		perror("chown: " TCB_DIR);
		return 1;
	}

	status = copy_from_tcb();

	chown(TCB_DIR, 0, st.st_gid);

	return status ? 1 : 0;
}
