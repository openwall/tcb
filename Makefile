all install install-non-root clean:
	$(MAKE) -C misc $@
	$(MAKE) -C libs $@
	$(MAKE) -C progs $@
	$(MAKE) -C pam_tcb $@

install-pam_unix install-pam_pwdb:
	$(MAKE) -C pam_tcb $@

install-sysusers install-sysusers-auth:
	$(MAKE) -C misc $@
