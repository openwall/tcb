all install install-non-root clean:
	$(MAKE) -C misc $@
	$(MAKE) -C libs $@
	$(MAKE) -C progs $@
	$(MAKE) -C pam_tcb $@

install-pam_unix:
	$(MAKE) -C pam_tcb $@
