include ../Make.defs

LIBTCB = libtcb.so.0
LIBTCB_LONG = $(LIBTCB).9.8
LIBNSS = libnss_tcb.so.2
LIBTCB_A = libtcb.a
LIB_MAP = libtcb.map
NSS_MAP = libnss_tcb.map

all: $(LIBTCB_LONG) $(LIBNSS) $(LIBTCB_A)

$(LIBTCB_A): libtcb_a.o
	ar -cr $@ $<
	ranlib $@

libtcb_a.o: libtcb.c
	$(CC) $(CFLAGS) $(DBGFLAG) -c $< -o $@

$(LIBTCB_LONG): libtcb.o $(LIB_MAP)
	$(CC) $(LDFLAGS) -shared -o $@ -Wl,-soname,$(LIBTCB) \
		-Wl,--version-script=$(LIB_MAP) $<
	ln -sf $@ $(LIBTCB)
	ln -sf $(LIBTCB) libtcb.so

$(LIBNSS): nss.o $(NSS_MAP) $(LIBTCB_LONG)
	$(CC) $(LDFLAGS) -shared -o $@ -Wl,-soname,$(LIBNSS) \
		-Wl,--version-script=$(NSS_MAP) $< -ltcb

.c.o:
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

install-non-root: install

install:
	$(MKDIR) -p -m 755 $(DESTDIR)$(SLIBDIR)
	$(MKDIR) -p -m 755 $(DESTDIR)$(LIBDIR)
	$(INSTALL) -m $(SHLIBMODE) $(LIBTCB_LONG) $(DESTDIR)$(SLIBDIR)/
	ln -sf $(LIBTCB_LONG) $(DESTDIR)$(SLIBDIR)/$(LIBTCB)
	ln -sf ../..$(SLIBDIR)/$(LIBTCB) $(DESTDIR)$(LIBDIR)/libtcb.so
	$(INSTALL) -m $(SHLIBMODE) $(LIBNSS) $(DESTDIR)$(SLIBDIR)/
	$(INSTALL) -m 644 $(LIBTCB_A) $(DESTDIR)$(LIBDIR)/

clean:
	rm -f *.o *~ $(LIBTCB)* libtcb.so $(LIBNSS) *.a
