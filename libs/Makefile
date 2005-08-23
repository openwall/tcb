include ../Make.defs

LIBTCB = libtcb.so.0
LIBTCB_LONG = $(LIBTCB).9.8
LIBNSS = libnss_tcb.so.2
LIBTCB_A = libtcb.a

all: $(LIBTCB_LONG) $(LIBNSS) $(LIBTCB_A)

$(LIBTCB_A): libtcb_a.o
	ar -cr $@ $<
	ranlib $@

libtcb_a.o: libtcb.c
	$(CC) $(CFLAGS) $(DBGFLAG) -c $< -o $@

$(LIBTCB_LONG): libtcb.o
	$(CC) $(DBGFLAG) -shared -o $@ -Wl,-soname,$(LIBTCB) $< -lc
	ln -sf $@ $(LIBTCB)
	ln -sf $(LIBTCB) libtcb.so

$(LIBNSS): nss.o $(LIBTCB_LONG)
	$(CC) $(DBGFLAG) -shared -o $@ $< -L. $(LIBNSL) -ltcb

.c.o:
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

install-non-root: install

install:
	mkdir -p $(DESTDIR)$(SLIBDIR)
	mkdir -p $(DESTDIR)$(LIBDIR)
	install -m $(SHLIBMODE) $(LIBTCB_LONG) $(DESTDIR)$(SLIBDIR)/
	ln -sf $(LIBTCB_LONG) $(DESTDIR)$(SLIBDIR)/$(LIBTCB)
	ln -sf ../..$(SLIBDIR)/$(LIBTCB) $(DESTDIR)$(LIBDIR)/libtcb.so
	install -m $(SHLIBMODE) $(LIBNSS) $(DESTDIR)$(SLIBDIR)/
	install -m 644 $(LIBTCB_A) $(DESTDIR)$(LIBDIR)/

clean:
	rm -f *.o *~ $(LIBTCB)* libtcb.so $(LIBNSS) *.a
