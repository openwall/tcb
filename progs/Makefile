include ../Make.defs

CONVERT = tcb_convert
UNCONVERT = tcb_unconvert
CHKPWD = tcb_chkpwd

all: $(CONVERT) $(UNCONVERT) $(CHKPWD)

$(CONVERT): $(CONVERT).o
	$(CC) -o $@ $<

$(UNCONVERT): $(UNCONVERT).o
	$(CC) -o $@ $< -L../libs -ltcb

$(CHKPWD): $(CHKPWD).o
	$(CC) -o $@ $< -lcrypt

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

install-non-root: install-common
	install -d -m 710 $(FAKEROOT)$(LIBEXECDIR)/chkpwd
	install -m 700 $(CHKPWD) $(FAKEROOT)$(LIBEXECDIR)/chkpwd/

install: install-common
	install -d -o root -g chkpwd -m 710 $(FAKEROOT)$(LIBEXECDIR)/chkpwd
	install -m 2711 -o root -g shadow $(CHKPWD) \
		$(FAKEROOT)$(LIBEXECDIR)/chkpwd/

install-common:
	install -m 700 $(CONVERT) $(FAKEROOT)$(SBINDIR)/
	install -m 700 $(UNCONVERT) $(FAKEROOT)$(SBINDIR)/
	install -m 644 $(CONVERT).8 $(FAKEROOT)/$(MANDIR)/man8/
	install -m 644 $(UNCONVERT).8 $(FAKEROOT)/$(MANDIR)/man8/

clean:
	rm -f $(CONVERT) $(UNCONVERT) $(CHKPWD) *.o *~
