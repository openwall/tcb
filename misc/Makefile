include ../Make.defs

all clean:

install-non-root: install

install:
	mkdir -p $(DESTDIR)/lib
	mkdir -p $(DESTDIR)$(SBINDIR)
	mkdir -p $(DESTDIR)$(LIBEXECDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man{5,8}
	mkdir -p $(DESTDIR)/usr/{lib,include}

	install -m 644 tcb.5 $(DESTDIR)$(MANDIR)/man5/
	install -m 644 ../include/tcb.h $(DESTDIR)/usr/include/
