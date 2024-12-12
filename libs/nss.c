#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shadow.h>
#include <nss.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

#include "tcb.h"

static DIR **get_thread_local_tcbdir(void)
{
	static __thread DIR *tcbdir = NULL;
	return &tcbdir;
}

int _nss_tcb_setspent(void)
{
	return 1;
}

int _nss_tcb_endspent(void)
{
	DIR **tcbdir = get_thread_local_tcbdir();

	if (*tcbdir) {
		closedir(*tcbdir);
		*tcbdir = NULL;
	}
	return 1;
}

static FILE *tcb_safe_open(const char *file, const char *name)
{
	gid_t grplist[TCB_NGROUPS];
	struct tcb_privs tp = { grplist, TCB_NGROUPS, -1, -1, 0 };
	FILE *f;
	int fd, saved_errno;

	if (tcb_drop_priv_r(name, &tp))
		return NULL;
	fd = open(file, O_RDONLY | O_NOCTTY | O_NONBLOCK | O_NOFOLLOW);
	saved_errno = errno;
	if (fd >= 0 && tcb_is_suspect(fd)) {
		close(fd);
		fd = -1;
		/* XXX: what would be the proper errno? */
		saved_errno = ENOENT;
	}
	tcb_gain_priv_r(&tp);
	errno = saved_errno;

	if (fd < 0)
		return 0;

	f = fdopen(fd, "r");
	if (!f)
		close(fd);

	return f;
}

int _nss_tcb_getspnam_r(const char *name, struct spwd *__result_buf,
    char *__buffer, size_t __buflen, struct spwd **__result)
{
	FILE *f;
	char *file;
	int retval, saved_errno;

	if (asprintf(&file, TCB_FMT, name) < 0)
		return NSS_STATUS_TRYAGAIN;
	f = tcb_safe_open(file, name);
	free(file);
	if (!f)
		return NSS_STATUS_UNAVAIL;

	retval = fgetspent_r(f, __result_buf, __buffer, __buflen, __result);
	saved_errno = errno;
	fclose(f);
	errno = saved_errno;
	if (!retval)
		return NSS_STATUS_SUCCESS;

	switch (saved_errno) {
	case 0:
		return NSS_STATUS_SUCCESS;

	case ENOENT:
		return NSS_STATUS_NOTFOUND;

	case ERANGE:
		return NSS_STATUS_TRYAGAIN;

	default:
		return NSS_STATUS_UNAVAIL;
	}
}

int _nss_tcb_getspent_r(struct spwd *__result_buf,
    char *__buffer, size_t __buflen, struct spwd **__result)
{
	DIR **tcbdir = get_thread_local_tcbdir();
	struct dirent *result;
	off_t currpos;
	int retval, saved_errno;

	if (!*tcbdir) {
		*tcbdir = opendir(TCB_DIR);
		if (!*tcbdir)
			return NSS_STATUS_UNAVAIL;
	}

	do {
		currpos = telldir(*tcbdir);
		saved_errno = errno;
		errno = 0;
		result = readdir(*tcbdir);
		if (!result && errno) {
			closedir(*tcbdir);
			errno = saved_errno;
			*tcbdir = NULL;
			return NSS_STATUS_UNAVAIL;
		}
		if (!result) {
			closedir(*tcbdir);
			errno = ENOENT;
			*tcbdir = NULL;
			return NSS_STATUS_NOTFOUND;
		}
		errno = saved_errno;
	} while (!strcmp(result->d_name, ".") ||
	    !strcmp(result->d_name, "..") || result->d_name[0] == ':');

	retval = _nss_tcb_getspnam_r(result->d_name, __result_buf, __buffer,
	    __buflen, __result);

	switch (retval) {
	case NSS_STATUS_SUCCESS:
		return NSS_STATUS_SUCCESS;

	case NSS_STATUS_TRYAGAIN:
		saved_errno = errno;
		seekdir(*tcbdir, currpos);
		errno = saved_errno;
		return NSS_STATUS_TRYAGAIN;

	default:
		saved_errno = errno;
		closedir(*tcbdir);
		errno = saved_errno;
		*tcbdir = NULL;
		return retval;
	}
}
