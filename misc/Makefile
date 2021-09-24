include ../Make.defs

all clean:

install-non-root: install

install:
	$(MKDIR) -p -m 755 $(DESTDIR)$(MANDIR)/man5
	$(MKDIR) -p -m 755 $(DESTDIR)/usr/include

	$(INSTALL) -m 644 tcb.5 $(DESTDIR)$(MANDIR)/man5/
	$(INSTALL) -m 644 ../include/tcb.h $(DESTDIR)/usr/include/
