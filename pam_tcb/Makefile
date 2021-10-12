include ../Make.defs

PAM_TCB = pam_tcb.so$(PAM_SO_SUFFIX)
PAM_MAP = pam_tcb.map

ifneq ($(PAM_SO_SUFFIX),)
PAM_TCB_SONAME = -Wl,-soname,$(PAM_TCB)
endif

LIBSRC = \
	pam_unix_auth.c pam_unix_acct.c pam_unix_sess.c pam_unix_passwd.c \
	support.c compat.c

LIBOBJ = $(LIBSRC:.c=.o)

all: $(PAM_TCB)

$(PAM_TCB): $(LIBOBJ) $(PAM_MAP)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $(PAM_TCB_SONAME) \
		-Wl,--version-script=$(PAM_MAP) $(LIBOBJ) -lcrypt -lpam -ltcb

.c.o:
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

pam_unix_acct.o: pam_unix_acct.c
	$(CC) $(CFLAGS) -DCHKPWD_HELPER=\"$(LIBEXECDIR)/chkpwd/tcb_chkpwd\" \
		-fPIC -c $< -o $@

support.o: support.c
	$(CC) $(CFLAGS) -DCHKPWD_HELPER=\"$(LIBEXECDIR)/chkpwd/tcb_chkpwd\" \
		-fPIC -c $< -o $@

install-non-root: install

install:
	$(MKDIR) -p -m 755 $(DESTDIR)$(SLIBDIR)/security
	$(MKDIR) -p -m 755 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m $(SHLIBMODE) $(PAM_TCB) $(DESTDIR)$(SLIBDIR)/security/
	$(INSTALL) -m 644 pam_tcb.8 $(DESTDIR)$(MANDIR)/man8/

install-pam_unix: install
	ln -s $(PAM_TCB) $(DESTDIR)$(SLIBDIR)/security/pam_unix.so$(PAM_SO_SUFFIX)
	ln -s $(PAM_TCB) $(DESTDIR)$(SLIBDIR)/security/pam_unix_acct.so$(PAM_SO_SUFFIX)
	ln -s $(PAM_TCB) $(DESTDIR)$(SLIBDIR)/security/pam_unix_auth.so$(PAM_SO_SUFFIX)
	ln -s $(PAM_TCB) $(DESTDIR)$(SLIBDIR)/security/pam_unix_passwd.so$(PAM_SO_SUFFIX)
	ln -s $(PAM_TCB) $(DESTDIR)$(SLIBDIR)/security/pam_unix_session.so$(PAM_SO_SUFFIX)
	$(INSTALL) -m 644 pam_unix.8 $(DESTDIR)$(MANDIR)/man8/

install-pam_pwdb: install
	ln -s $(PAM_TCB) $(DESTDIR)$(SLIBDIR)/security/pam_pwdb.so$(PAM_SO_SUFFIX)
	$(INSTALL) -m 644 pam_pwdb.8 $(DESTDIR)$(MANDIR)/man8/

clean:
	rm -f *.o *~ $(PAM_TCB)*
