# $Owl$

Summary: Libraries and tools implementing the tcb password shadowing scheme.
Name: tcb
Version: 1.2
Release: owl1
License: BSD or GPL
Group: System Environment/Base
URL: http://www.openwall.com/tcb/
Source: ftp://ftp.openwall.com/pub/projects/tcb/%name-%version.tar.gz
Requires: %_libexecdir/chkpwd
Requires: glibc-crypt_blowfish >= 1.2
# Due to pam_pwdb.so
Conflicts: pam < 0:0.80-owl1
BuildRequires: glibc-crypt_blowfish-devel, pam-devel
BuildRoot: /override/%name-%version

%description
The tcb package consists of three components: pam_tcb, libnss_tcb, and
libtcb.  pam_tcb is a PAM module which supersedes pam_unix and pam_pwdb.
It also implements the tcb password shadowing scheme (see tcb(5) for
details).  The tcb scheme allows many core system utilities (passwd(1)
being the primary example) to operate with little privilege.  libnss_tcb
is the accompanying NSS module.  libtcb contains code shared by the
PAM and NSS modules and is also used by programs from the shadow-utils
package.

%package devel
Summary: Libraries and header files for building tcb-aware applications.
Group: Development/Libraries
Requires: %name = %version-%release

%description devel
This package contains static libraries and header files needed for
building tcb-aware applications.

%prep
%setup -q

%build
CFLAGS="%optflags -DENABLE_SETFSUGID" %__make

%install
rm -rf %buildroot
make install-non-root install-pam_unix install-pam_pwdb DESTDIR=%buildroot \
	MANDIR=%_mandir LIBDIR=%_libdir SLIBDIR=/%_lib

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%triggerin -- shadow-utils
grep -q '^shadow:[^:]*:42:' /etc/group && \
	chgrp shadow %_libexecdir/chkpwd/tcb_chkpwd && \
	chmod 2711 %_libexecdir/chkpwd/tcb_chkpwd
grep -q ^chkpwd: /etc/group || groupadd -g 163 chkpwd
chgrp chkpwd %_libexecdir/chkpwd && chmod 710 %_libexecdir/chkpwd

# This is needed for upgrades from older versions of the package.
%triggerpostun -- tcb < 0.9.7.1
rmdir /sbin/chkpwd.d

%files
%defattr(-,root,root)
%doc LICENSE
/%_lib/libnss_tcb.so.2
/%_lib/libtcb.so.*
/%_lib/security/pam_pwdb.so
/%_lib/security/pam_tcb.so
/%_lib/security/pam_unix.so
/%_lib/security/pam_unix_acct.so
/%_lib/security/pam_unix_auth.so
/%_lib/security/pam_unix_passwd.so
/%_lib/security/pam_unix_session.so
/sbin/tcb_convert
/sbin/tcb_unconvert
%attr(0700,root,root) %verify(not mode group) %dir %_libexecdir/chkpwd
%attr(0700,root,root) %verify(not mode group) %_libexecdir/chkpwd/tcb_chkpwd
%_mandir/man5/tcb.5*
%_mandir/man8/pam_pwdb.8*
%_mandir/man8/pam_tcb.8*
%_mandir/man8/pam_unix.8*
%_mandir/man8/tcb_convert.8*
%_mandir/man8/tcb_unconvert.8*

%files devel
%defattr(-,root,root)
%_includedir/tcb.h
%_libdir/libtcb.a
%_libdir/libtcb.so
%_libdir/pkgconfig/tcb.pc

%changelog
* Mon Jan 11 2021 Solar Designer <solar-at-owl.openwall.com> 1.2-owl1
- 1.2 release with Dmitry's post-1.1.9.1 cleanups implemented in mid-2020 and
described in ChangeLog, most notably:
+ tcb_chkpwd: remove the last remaining piece of NIS+ support.

* Sat Jul 07 2018 Dmitry V. Levin <ldv-at-owl.openwall.com> 1.1.9.1-owl1
- pam_tcb:
+ Implemented i18n support which is off by default, it can be enabled by
defining both ENABLE_NLS and NLS_PACKAGE macros.
+ Dropped obsolete NIS/NIS+ support.
+ Dropped support for not_set_pass option, introduced authtok_type= option
instead, following the change in pam_unix implemented in Linux-PAM-1.3.0.
+ Synced password expiration messages with Linux-PAM-1.4.0.
+ Changed crypt_gensalt_ra invocation to use default entropy and hash encoding
prefix provided by libcrypt runtime when libxcrypt >= 4.1.0 is used for build.
+ Changed the default hash encoding prefix from $2y$ to $2b$.

* Mon Jun 30 2014 (GalaxyMaster) <galaxy-at-owl.openwall.com> 1.1-owl2
- Removed the deprecated PreReq tag.

* Sun Jul 17 2011 Solar Designer <solar-at-owl.openwall.com> 1.1-owl1
- Changed the default hash encoding prefix from "$2a$" to "$2y$" (requires
crypt_blowfish 1.2 or newer).

* Mon Jun 07 2010 Dmitry V. Levin <ldv-at-owl.openwall.com> 1.0.6-owl1
- Dropped faulty check for sparse files in tcb_is_suspect().

* Thu Feb 25 2010 Dmitry V. Levin <ldv-at-owl.openwall.com> 1.0.5-owl1
- Decreased the size of tcb_privs structure allocated in .data segment
from 256K to a two dozen bytes by moving a groups array to .bss segment.

* Wed Feb 10 2010 Dmitry V. Levin <ldv-at-owl.openwall.com> 1.0.4-owl1
- Fixed potential grpbuf buffer overflow in tcb_drop_priv_r().  There
doesn't appear to be any untrusted user input involved, so this bug
doesn't have to be treated as a security issue.
- Patched Makefiles to use LDFLAGS more consistently.  Reported by
Paweł Hajdan.

* Fri Apr 03 2009 Dmitry V. Levin <ldv-at-owl.openwall.com> 1.0.3-owl1
- In the PAM module, replaced all calls to exit(3) in child processes
with calls to _exit(2).  Reported by Pascal Terjan.
- In the PAM module, added fflush(3) and fsync(2) calls right before
closing file opened for writing.  Reported by Ermanno Scaglione.

* Tue Oct 31 2006 Dmitry V. Levin <ldv-at-owl.openwall.com> 1.0.2-owl1
- In the PAM module and tcb_chkpwd helper, fixed memory leaks reported
by Alexander Kanevskiy.

* Sat May 06 2006 Dmitry V. Levin <ldv-at-owl.openwall.com> 1.0.1-owl1
- In the PAM module, hardened pam_sm_open_session() to fail for unknown users.

* Wed Dec 28 2005 Dmitry V. Levin <ldv-at-owl.openwall.com> 1.0-owl1
- Fixed potential NULL dereferences in the PAM module password handling.
- Removed user prompt override in calls to pam_get_user.
- Implemented OpenPAM build support.
- Updated logging code to use pam_syslog.
- Updated conversation code to use pam_prompt.

* Tue Aug 23 2005 Dmitry V. Levin <ldv-at-owl.openwall.com> 0.9.9-owl1
- Restricted list of global symbols exported by the library,
NSS and PAM modules.
- In the PAM module, implemented "openlog" option and disabled
openlog/closelog calls for each logging function invocation,
according to new convention introduced in pam-0.80-owl1.
- Packaged pam_pwdb.so symlink in addition to pam_unix.so.
- Packaged %_libexecdir/chkpwd directory.

* Fri Apr 22 2005 Dmitry V. Levin <ldv-at-owl.openwall.com> 0.9.8.9-owl1
- Deal with compilation warnings generated by new gcc compiler.

* Wed Jan 05 2005 (GalaxyMaster) <galaxy-at-owl.openwall.com> 0.9.8.8-owl2
- Tell RPM to not verify permissions and group ownership of tcb_chkpwd since
we're setting the correct permissions via a trigger on shadow-utils.
- Cleaned up the spec.

* Fri Jun 25 2004 Dmitry V. Levin <ldv-at-owl.openwall.com> 0.9.8.8-owl1
- tcb_unconvert: Zero errno before each readdir(3) call.

* Sun Nov 02 2003 Solar Designer <solar-at-owl.openwall.com> 0.9.8.7-owl1
- Build the PAM module with -fPIC.
- Renamed FAKEROOT to DESTDIR.

* Wed Oct 29 2003 Solar Designer <solar-at-owl.openwall.com> 0.9.8.6-owl1
- Don't depend on *BSD-style asprintf(3) semantics as Ulrich has rejected
that patch.
- Require glibc-crypt_blowfish-devel for builds, but just glibc-crypt_blowfish
for package installation.

* Fri Apr 18 2003 Solar Designer <solar-at-owl.openwall.com> 0.9.8.5-owl1
- Use bold face for component names in .SH NAME, but avoid *roff commands
to not confuse makewhatis and apropos(1).

* Wed Apr 16 2003 Dmitry V. Levin <ldv-at-owl.openwall.com> 0.9.8.4-owl1
- In pam_tcb, implemented proper fake salt creation to avoid a timing attack.

* Thu Oct 31 2002 Solar Designer <solar-at-owl.openwall.com>
- Optimized unix_verify_password() a bit, from Dmitry V. Levin of ALT Linux.

* Wed Oct 30 2002 Solar Designer <solar-at-owl.openwall.com>
- In tcb_convert.8, noted that /etc/shadow backups need to be removed as
well, with /etc/shadow- as the particular example.

* Thu Oct 24 2002 Solar Designer <solar-at-owl.openwall.com>
- Cleaned up the recent changes.

* Mon Aug 19 2002 Rafal Wojtczuk <nergal-at-owl.openwall.com>
- Merged enhancements which remove 32K users limit.
- Added ENABLE_SETFSUGID.
- Pass the username to the helper binary such that it can handle non-unique
UIDs.

* Mon Aug 19 2002 Solar Designer <solar-at-owl.openwall.com>
- Moved libtcb.so symlink to /usr/lib (patch from Dmitry V. Levin).

* Sun Aug 04 2002 Solar Designer <solar-at-owl.openwall.com>
- Moved the pam_tcb and pam_unix manual pages to section 8.

* Sun Jul 07 2002 Solar Designer <solar-at-owl.openwall.com>
- No longer let root enforced password changes (sp_lstchg == 0) take
precedence over expired accounts (sp_expire).

* Sun May 19 2002 Solar Designer <solar-at-owl.openwall.com>
- Moved the chkpwd directory to /usr/libexec.

* Mon Feb 04 2002 Solar Designer <solar-at-owl.openwall.com>
- Enforce our new spec file conventions.

* Sun Dec 09 2001 Solar Designer <solar-at-owl.openwall.com>
- Various minor fixes from Dmitry V. Levin of ALT Linux.
- A GNU-style ChangeLog will now be maintained.

* Sun Nov 18 2001 Solar Designer <solar-at-owl.openwall.com>
- Patches from Nergal to make delays on failure work with the "fork"
option and to not produce a warning when su'ing to pseudo-users from
root.

* Fri Nov 16 2001 Solar Designer <solar-at-owl.openwall.com>
- Don't include the /sbin/chkpwd.d directory in this package as it's
provided by our pam package.
- Use a trigger on shadow-utils for possibly creating and making use of
group shadow.  This makes no difference on Owl as either the group is
provided by owl-etc (on new installs) or groupadd is already available
when this package is installed, but may be useful on hybrid systems.

* Thu Nov 15 2001 Solar Designer <solar-at-owl.openwall.com>
- Provide compatibility symlinks and a man page for pam_unix.
- tcb_convert(8) man page fixes from Nergal.
- Moved all of pam_tcb's prompts and messages to support.h and made them
more consistent with those used by pam_passwdqc.
- Improved logging.

* Thu Nov 01 2001 Solar Designer <solar-at-owl.openwall.com>
- Changed everything all over the place during October. ;-)

* Tue Sep 11 2001 Rafal Wojtczuk <nergal-at-owl.openwall.com>
- Makefiles and code layout rewrite.
- Added reentrant tcb_*_privs_r() functions, needed for nss.

* Sun Aug 19 2001 Rafal Wojtczuk <nergal-at-owl.openwall.com>
- version 0.5
- man pages
- nis fixes
- removed ugly _unix_getpwnam(), clean replacement

* Sat Aug 04 2001 Rafal Wojtczuk <nergal-at-owl.openwall.com>
- 0.4 packaged for Owl.
