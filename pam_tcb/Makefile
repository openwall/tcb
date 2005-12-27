include ../Make.defs

PAM_TCB = pam_tcb.so
PAM_MAP = pam_tcb.map

LIBSRC = \
	pam_unix_auth.c pam_unix_acct.c pam_unix_sess.c pam_unix_passwd.c \
	support.c compat.c yppasswd_xdr.c

LIBOBJ = $(LIBSRC:.c=.o)

all: $(PAM_TCB)

$(PAM_TCB): $(LIBOBJ) $(PAM_MAP)
	$(CC) $(LDFLAGS) -shared -o $@ -Wl,--version-script=$(PAM_MAP) \
		$(LIBOBJ) -lnsl -lcrypt -lpam -ltcb

.c.o:
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

support.o: support.c
	$(CC) $(CFLAGS) -DCHKPWD_HELPER=\"$(LIBEXECDIR)/chkpwd/tcb_chkpwd\" \
		-fPIC -c $< -o $@

install-non-root: install

install:
	mkdir -p $(DESTDIR)$(SLIBDIR)/security
	mkdir -p $(DESTDIR)$(MANDIR)/man8
	install -m $(SHLIBMODE) $(PAM_TCB) $(DESTDIR)$(SLIBDIR)/security/
	install -p -m 644 pam_tcb.8 $(DESTDIR)$(MANDIR)/man8/

install-pam_unix: install
	ln -s $(PAM_TCB) $(DESTDIR)$(SLIBDIR)/security/pam_unix.so
	ln -s $(PAM_TCB) $(DESTDIR)$(SLIBDIR)/security/pam_unix_acct.so
	ln -s $(PAM_TCB) $(DESTDIR)$(SLIBDIR)/security/pam_unix_auth.so
	ln -s $(PAM_TCB) $(DESTDIR)$(SLIBDIR)/security/pam_unix_passwd.so
	ln -s $(PAM_TCB) $(DESTDIR)$(SLIBDIR)/security/pam_unix_session.so
	install -p -m 644 pam_unix.8 $(DESTDIR)$(MANDIR)/man8/

install-pam_pwdb: install
	ln -s $(PAM_TCB) $(DESTDIR)$(SLIBDIR)/security/pam_pwdb.so
	install -p -m 644 pam_pwdb.8 $(DESTDIR)$(MANDIR)/man8/

clean:
	rm -f *.o *~ $(PAM_TCB)
