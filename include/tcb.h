#ifndef _TCB_H
#define _TCB_H

#include <sys/types.h>
#include <limits.h>
#include <grp.h>

#define TCB_DIR				"/etc/tcb"
#define TCB_FMT				TCB_DIR "/%s/shadow"

#define TCB_NGROUPS			NGROUPS_MAX

struct tcb_privs {
	gid_t grpbuf[TCB_NGROUPS];
	int saved_groups;
	gid_t old_gid;
	uid_t old_uid;
	int is_dropped;
};

extern int lckpwdf_tcb(const char *);
extern int ulckpwdf_tcb(void);
extern int tcb_drop_priv(const char *);
extern int tcb_gain_priv(void);
extern int tcb_drop_priv_r(const char *, struct tcb_privs *);
extern int tcb_gain_priv_r(struct tcb_privs *);
extern int tcb_is_suspect(int);

#endif
