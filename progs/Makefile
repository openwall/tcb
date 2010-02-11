include ../Make.defs

CONVERT = tcb_convert
UNCONVERT = tcb_unconvert
CHKPWD = tcb_chkpwd

all: $(CONVERT) $(UNCONVERT) $(CHKPWD)

$(CONVERT): $(CONVERT).o
	$(CC) $(LDFLAGS) -o $@ $<

$(UNCONVERT): $(UNCONVERT).o
	$(CC) $(LDFLAGS) -o $@ $< -ltcb

$(CHKPWD): $(CHKPWD).o
	$(CC) $(LDFLAGS) -o $@ $< -lcrypt

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

install-non-root: install-common
	install -d -m 710 $(DESTDIR)$(LIBEXECDIR)/chkpwd
	install -m 700 $(CHKPWD) $(DESTDIR)$(LIBEXECDIR)/chkpwd/

install: install-common
	install -d -o root -g chkpwd -m 710 $(DESTDIR)$(LIBEXECDIR)/chkpwd
	install -m 2711 -o root -g shadow $(CHKPWD) \
		$(DESTDIR)$(LIBEXECDIR)/chkpwd/

install-common:
	mkdir -p $(DESTDIR)$(SBINDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man8
	install -m 700 $(CONVERT) $(DESTDIR)$(SBINDIR)/
	install -m 700 $(UNCONVERT) $(DESTDIR)$(SBINDIR)/
	install -m 644 $(CONVERT).8 $(DESTDIR)$(MANDIR)/man8/
	install -m 644 $(UNCONVERT).8 $(DESTDIR)$(MANDIR)/man8/

clean:
	rm -f $(CONVERT) $(UNCONVERT) $(CHKPWD) *.o *~
