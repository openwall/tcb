include ../Make.defs

all: tcb.sysusers

tcb.sysusers: tcb.sysusers.in
	sed -e "s!@LIBEXECDIR@!$(LIBEXECDIR)!g" < $< > $@

install-non-root: install

install:
	$(MKDIR) -p -m 755 $(DESTDIR)$(MANDIR)/man5
	$(MKDIR) -p -m 755 $(DESTDIR)/usr/include

	$(INSTALL) -m 644 tcb.5 $(DESTDIR)$(MANDIR)/man5/
	$(INSTALL) -m 644 ../include/tcb.h $(DESTDIR)/usr/include/

install-sysusers:
	$(MKDIR) -p -m 755 $(DESTDIR)$(SYSUSERSDIR)
	$(INSTALL) -m 644 tcb.sysusers $(DESTDIR)$(SYSUSERSDIR)/tcb.conf

install-sysusers-auth: install-sysusers
	$(INSTALL) -m 644 tcb-auth.sysusers $(DESTDIR)$(SYSUSERSDIR)/tcb-auth.conf

clean:
	rm -f tcb.sysusers
