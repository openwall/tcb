include ../Make.defs

all clean:

install-non-root: install

install:
	mkdir -p $(FAKEROOT)/lib
	mkdir -p $(FAKEROOT)/usr/lib
	mkdir -p $(FAKEROOT)$(SECUREDIR)
	mkdir -p $(FAKEROOT)$(SYSBIN)
	mkdir -p $(FAKEROOT)/usr/include
	mkdir -p $(FAKEROOT)/$(MANDIR)/man5
	mkdir -p $(FAKEROOT)/$(MANDIR)/man8
	mkdir -p $(FAKEROOT)/usr/include

	install -m 644 tcb.5 $(FAKEROOT)/$(MANDIR)/man5
	install -m 644 ../include/tcb.h $(FAKEROOT)/usr/include
