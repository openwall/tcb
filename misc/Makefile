include ../Make.defs

all clean:

install-non-root: install

install:
	mkdir -p $(FAKEROOT)/lib
	mkdir -p $(FAKEROOT)$(SBINDIR)
	mkdir -p $(FAKEROOT)$(LIBEXECDIR)
	mkdir -p $(FAKEROOT)/$(MANDIR)/man{5,8}
	mkdir -p $(FAKEROOT)/usr/{lib,include}

	install -m 644 tcb.5 $(FAKEROOT)/$(MANDIR)/man5/
	install -m 644 ../include/tcb.h $(FAKEROOT)/usr/include/
