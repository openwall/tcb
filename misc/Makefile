include ../Make.defs

VERSION != sed -e "/^Version: */!d;s///;q" < ../tcb.spec

all: tcb.pc tcb.sysusers

tcb.pc: tcb.pc.in
	sed -e "s!@PREFIX@!$(PREFIX)!g" -e "s!@SLIBDIR@!$(SLIBDIR)!g" \
		-e "s!@INCLUDEDIR@!$(INCLUDEDIR)!g" -e "s!@VERSION@!$(VERSION)!g" \
		< $< > $@

tcb.sysusers: tcb.sysusers.in
	sed -e "s!@LIBEXECDIR@!$(LIBEXECDIR)!g" < $< > $@

install-non-root: install

install:
	$(MKDIR) -p -m 755 $(DESTDIR)$(MANDIR)/man5
	$(MKDIR) -p -m 755 $(DESTDIR)$(INCLUDEDIR)
	$(MKDIR) -p -m 755 $(DESTDIR)$(PKGCONFIGDIR)

	$(INSTALL) -m 644 tcb.5 $(DESTDIR)$(MANDIR)/man5/
	$(INSTALL) -m 644 ../include/tcb.h $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL) -m 644 tcb.pc $(DESTDIR)$(PKGCONFIGDIR)

install-sysusers:
	$(MKDIR) -p -m 755 $(DESTDIR)$(SYSUSERSDIR)
	$(INSTALL) -m 644 tcb.sysusers $(DESTDIR)$(SYSUSERSDIR)/tcb.conf

install-sysusers-auth: install-sysusers
	$(INSTALL) -m 644 tcb-auth.sysusers $(DESTDIR)$(SYSUSERSDIR)/tcb-auth.conf

clean:
	rm -f tcb.pc tcb.sysusers
