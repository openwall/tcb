include ./Make.defs

all install install-non-root clean:
	$(MAKE) -C misc $@
	$(MAKE) -C libs $@
	$(MAKE) -C progs $@
ifeq ($(OMIT_PAM_MODULE),)
	$(MAKE) -C pam_tcb $@
endif

install-pam_unix install-pam_pwdb:
	$(MAKE) -C pam_tcb $@

install-sysusers install-sysusers-auth:
	$(MAKE) -C misc $@
