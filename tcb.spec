# $Id: tcb.spec,v 1.2 2001/11/15 04:45:06 solar Exp $

Summary: Libraries and tools implementing the tcb password shadowing scheme.
Name: tcb
Version: 0.9.5
Release: 2owl
License: BSD or GPL
Group: System Environment/Base
Source: %{name}-%{version}.tar.gz
PreReq: pam >= 0.75-12owl, /sbin/chkpwd.d
BuildRequires: glibc-devel >= 2.1.3-13owl, pam-devel
BuildRoot: /override/%{name}-%{version}

%description
The tcb package consists of three components: pam_tcb, libnss_tcb, and
libtcb.  pam_tcb is a PAM module which supersedes pam_unix.  It also
implements the tcb password shadowing scheme (see tcb(5) for details).
The tcb scheme allows many core system utilities (passwd(1) being the
primary example) to operate with little privilege.  libnss_tcb is the
accompanying NSS module.  libtcb contains code shared by the PAM and
NSS modules and is also used by programs from the shadow-utils package.

%package devel
Summary: Libraries and header files for building tcb-aware applications.
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
This package contains static libraries and header files needed for
building tcb-aware applications.

%prep
%setup -q

%build
CFLAGS="$RPM_OPT_FLAGS" make

%install
rm -rf $RPM_BUILD_ROOT
make install-non-root install-pam_unix FAKEROOT=$RPM_BUILD_ROOT MANDIR=%_mandir

%clean
rm -rf $RPM_BUILD_ROOT

%triggerin -- shadow-utils
grep -q '^shadow:[^:]*:42:' /etc/group && \
	chgrp shadow /sbin/chkpwd.d/tcb_chkpwd && \
	chmod 2711 /sbin/chkpwd.d/tcb_chkpwd

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%defattr(-,root,root)
%doc LICENSE
/lib/libnss_tcb.so.2
/lib/libtcb.so.*
/lib/libtcb.so
/lib/security/pam_tcb.so
/lib/security/pam_unix.so
/lib/security/pam_unix_acct.so
/lib/security/pam_unix_auth.so
/lib/security/pam_unix_passwd.so
/lib/security/pam_unix_session.so
/sbin/tcb_convert
/sbin/tcb_unconvert
%attr(0700,root,root) /sbin/chkpwd.d/tcb_chkpwd
/sbin/tcb_chkpwd
%_mandir/man5/tcb.5.*
%_mandir/man5/pam_tcb.5.*
%_mandir/man5/pam_unix.5.*
%_mandir/man8/tcb_convert.8.*
%_mandir/man8/tcb_unconvert.8.*

%files devel
%defattr(-,root,root)
/usr/include/tcb.h
/usr/lib/libtcb.a

%changelog
* Fri Nov 16 2001 Solar Designer <solar@owl.openwall.com>
- Don't include the /sbin/chkpwd.d directory in this package as it's
provided by our pam package.
- Use a trigger on shadow-utils for possibly creating and making use of
group shadow.  This makes no difference on Owl as either the group is
provided by owl-etc (on new installs) or groupadd is already available
when this package is installed, but may be useful on hybrid systems.

* Thu Nov 15 2001 Solar Designer <solar@owl.openwall.com>
- Provide compatibility symlinks and a man page for pam_unix.
- tcb_convert(8) man page fixes from Nergal.
- Moved all of pam_tcb's prompts and messages to support.h and made them
more consistent with those used by pam_passwdqc.
- Improved logging.

* Thu Nov 01 2001 Solar Designer <solar@owl.openwall.com>
- Changed everything all over the place during October. ;-)

* Tue Sep 11 2001 Rafal Wojtczuk <nergal@owl.openwall.com>
- Makefiles and code layout rewrite.
- Added reentrant tcb_*_privs_r() functions, needed for nss.

* Sun Aug 19 2001 Rafal Wojtczuk <nergal@owl.openwall.com>
- version 0.5
- man pages
- nis fixes
- removed ugly _unix_getpwnam(), clean replacement

* Sat Aug 04 2001 Rafal Wojtczuk <nergal@owl.openwall.com>
- 0.4 packaged for Owl.
