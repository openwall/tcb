include ../Make.defs

CONVERT = tcb_convert
UNCONVERT = tcb_unconvert
CHKPWD = tcb_chkpwd

all: $(CONVERT) $(UNCONVERT) $(CHKPWD)

$(CONVERT): $(CONVERT).o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(UNCONVERT): $(UNCONVERT).o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -ltcb

$(CHKPWD): $(CHKPWD).o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lcrypt

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

install-non-root: install-common
	$(INSTALL) -d -m 710 $(DESTDIR)$(LIBEXECDIR)/chkpwd
	$(INSTALL) -m 700 $(CHKPWD) $(DESTDIR)$(LIBEXECDIR)/chkpwd/

install: install-common
	$(INSTALL) -d -o root -g chkpwd -m 710 $(DESTDIR)$(LIBEXECDIR)/chkpwd
	$(INSTALL) -m 2711 -o root -g shadow $(CHKPWD) \
		$(DESTDIR)$(LIBEXECDIR)/chkpwd/

install-common:
	$(MKDIR) -p -m 755 $(DESTDIR)$(SBINDIR)
	$(MKDIR) -p -m 755 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 700 $(CONVERT) $(DESTDIR)$(SBINDIR)/
	$(INSTALL) -m 700 $(UNCONVERT) $(DESTDIR)$(SBINDIR)/
	$(INSTALL) -m 644 $(CONVERT).8 $(DESTDIR)$(MANDIR)/man8/
	$(INSTALL) -m 644 $(UNCONVERT).8 $(DESTDIR)$(MANDIR)/man8/

clean:
	rm -f $(CONVERT) $(UNCONVERT) $(CHKPWD) *.o *~
