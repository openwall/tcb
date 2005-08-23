include ../Make.defs

all clean:

install-non-root: install

install:
	mkdir -p $(DESTDIR)$(MANDIR)/man5
	mkdir -p $(DESTDIR)/usr/include

	install -m 644 tcb.5 $(DESTDIR)$(MANDIR)/man5/
	install -m 644 ../include/tcb.h $(DESTDIR)/usr/include/
