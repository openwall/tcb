include ../Make.defs

PAM_TCB = pam_tcb.so

LIBSRC = \
	pam_unix_auth.c pam_unix_acct.c pam_unix_sess.c pam_unix_passwd.c \
	support.c yppasswd_xdr.c

LIBOBJ = $(LIBSRC:.c=.o)

all: $(PAM_TCB)

$(PAM_TCB): $(LIBOBJ)
	$(CC) $(LDFLAGS) -shared -o $@ $(LIBOBJ) -lnsl -lcrypt -ltcb

.c.o:
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

support.o: support.c
	$(CC) $(CFLAGS) -DCHKPWD_HELPER=\"$(LIBEXECDIR)/chkpwd/tcb_chkpwd\" \
		-fPIC -c $< -o $@

install-non-root: install

install:
	mkdir -p $(DESTDIR)/lib/security
	install -m $(SHLIBMODE) $(PAM_TCB) $(DESTDIR)/lib/security/
	install -m 644 pam_tcb.8 $(DESTDIR)$(MANDIR)/man8/

install-pam_unix:
	ln -s $(PAM_TCB) $(DESTDIR)/lib/security/pam_unix.so
	ln -s $(PAM_TCB) $(DESTDIR)/lib/security/pam_unix_acct.so
	ln -s $(PAM_TCB) $(DESTDIR)/lib/security/pam_unix_auth.so
	ln -s $(PAM_TCB) $(DESTDIR)/lib/security/pam_unix_passwd.so
	ln -s $(PAM_TCB) $(DESTDIR)/lib/security/pam_unix_session.so
	install -m 644 pam_unix.8 $(DESTDIR)$(MANDIR)/man8/

clean:
	rm -f *.o *~ $(PAM_TCB)
