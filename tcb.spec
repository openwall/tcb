# $Id$

Summary: Libraries and tools implementing the tcb password shadowing scheme.
Name: tcb
Version: 0.9.4
Release: 1owl
License: GPL or BSD
Group: System Environment/Base
Source: %{name}-%{version}.tar.gz
BuildRequires: glibc-devel >= 2.1.3-13owl, pam-devel
PreReq: pam >= 0.75-11owl
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
make install-non-root FAKEROOT=$RPM_BUILD_ROOT MANDIR=%_mandir

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%defattr(-,root,root)
%doc LICENSE
/lib/libnss_tcb.so.2
/lib/libtcb.so.*
/lib/libtcb.so
/lib/security/pam_tcb.so
/sbin/tcb_convert
/sbin/tcb_unconvert
%attr(0710,root,chkpwd) %dir /sbin/chkpwd.d
%attr(02711,root,shadow) /sbin/chkpwd.d/tcb_chkpwd
/sbin/tcb_chkpwd
%_mandir/man5/tcb.5.*
%_mandir/man5/pam_tcb.5.*
%_mandir/man8/tcb_convert.8.*
%_mandir/man8/tcb_unconvert.8.*

%files devel
%defattr(-,root,root)
/usr/include/tcb.h
/usr/lib/libtcb.a

%changelog
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
