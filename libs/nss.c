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

static __thread DIR *tcbdir = NULL;

enum nss_status _nss_tcb_setspent(void)
{
	if (!tcbdir) {
		tcbdir = opendir(TCB_DIR);
		if (!tcbdir)
			return NSS_STATUS_UNAVAIL;

		return NSS_STATUS_SUCCESS;
	}

	rewinddir(tcbdir);
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_tcb_endspent(void)
{
	if (tcbdir) {
		closedir(tcbdir);
		tcbdir = NULL;
	}
	return NSS_STATUS_SUCCESS;
}

/******************************************************************************
IEEE Std 1003.1-2001 allows only the following characters to appear in group-
and usernames: letters, digits, underscores, periods, <at>-signs (@), and
dashes.  The name may not start with a dash or an "@" sign.  The "$" sign
is allowed at the end of usernames to allow typical Samba machine accounts.
******************************************************************************/
static int
is_valid_username (const char *un)
{
	if (!un || !*un || un[0] == '-' || un[0] == '@' ||
	    /* curdir || parentdir */
	    !strcmp(un, ".") || !strcmp(un, ".."))
		return 0;

	do {
		char c = *un++;
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '-' || c == '.' ||
		    c == '@' || c == '_' || (!*un && c == '$')))
			return 0;
	} while (*un);

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

enum nss_status _nss_tcb_getspnam_r(const char *name,
    struct spwd *__result_buf, char *__buffer, size_t __buflen, int *__errnop)
{
	FILE *f;
	char *file;
	int retval, saved_errno;

	/* Disallow potentially-malicious user names */
	if (!is_valid_username(name)) {
		/* we don't serve an entry here */
		*__errnop = ENOENT;
		return NSS_STATUS_NOTFOUND;
	}

	if (asprintf(&file, TCB_FMT, name) < 0) {
		/* retry, as malloc or another resource has failed */
		*__errnop = EAGAIN;
		return NSS_STATUS_TRYAGAIN;
	}

	f = tcb_safe_open(file, name);
	free(file);
	if (!f) {
		/* $user/shadow not existing nor readable */
		*__errnop = ENOENT;
		return NSS_STATUS_UNAVAIL;
	}

	retval = fgetspent_r(f, __result_buf, __buffer,
	    __buflen, &__result_buf);
	saved_errno = errno;
	fclose(f);
	errno = saved_errno;

	/* real error number is retval from fgetspent_r(),
	   by NSS spec errnop *MUST NOT* be set to 0 */
	if (retval)
		*__errnop = retval;

	switch (retval) {
	case 0:
		/* no error, entry found */
		return NSS_STATUS_SUCCESS;

	case ENOENT:
		/* if the file would not exist nor be readable, we would
		   have already bailed out with ENOENT/NSS_STATUS_UNAVAIL
		   immediately after the call to tcb_safe_open() */
		return NSS_STATUS_NOTFOUND;

	case EAGAIN:
		/* ressources are temporary not available */
		return NSS_STATUS_TRYAGAIN;

	case ERANGE:
		/* buffer too small */
		return NSS_STATUS_TRYAGAIN;

	default:
		/* something else, e.g. parser error, but we can't help it */
		return NSS_STATUS_UNAVAIL;
	}
}

enum nss_status _nss_tcb_getspent_r(struct spwd *__result_buf,
    char *__buffer, size_t __buflen, int *__errnop)
{
	struct dirent *result;
	off_t currpos;
	int retval, saved_errno;

	if (!tcbdir) {
		/* tcbdir does not exist */
		*__errnop = ENOENT;
		return NSS_STATUS_UNAVAIL;
	}

	do {
		currpos = telldir(tcbdir);
		saved_errno = errno;
		errno = 0;
		result = readdir(tcbdir);
		if (!result && errno) {
			closedir(tcbdir);
			errno = saved_errno;
			tcbdir = NULL;
			/* cannot iterate tcbdir */
			*__errnop = ENOENT;
			return NSS_STATUS_UNAVAIL;
		}
		if (!result) {
			closedir(tcbdir);
			errno = saved_errno;
			tcbdir = NULL;
			/* we have no more entries in tcbdir */
			*__errnop = ENOENT;
			return NSS_STATUS_NOTFOUND;
		}
		errno = saved_errno;
	} while (!strcmp(result->d_name, ".") ||
	    !strcmp(result->d_name, "..") || result->d_name[0] == ':');

	retval = _nss_tcb_getspnam_r(result->d_name, __result_buf, __buffer,
	    __buflen, __errnop);

	/* errnop has already been set by _nss_tcb_getspnam_r() */
	switch (retval) {
	case NSS_STATUS_SUCCESS:
		return NSS_STATUS_SUCCESS;

	case NSS_STATUS_TRYAGAIN:
		saved_errno = errno;
		seekdir(tcbdir, currpos);
		errno = saved_errno;
		return NSS_STATUS_TRYAGAIN;

	default:
		saved_errno = errno;
		closedir(tcbdir);
		errno = saved_errno;
		tcbdir = NULL;
		return retval;
	}
}
