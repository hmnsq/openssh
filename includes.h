/* $OpenBSD: includes.h,v 1.54 2006/07/22 20:48:23 stevesk Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file includes most of the needed system headers.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ INCLUDES_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ INCLUDES_H

#ਅਨ੍ਤਰ੍ਭਾਵ "config.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ GNU_ਸਰੋਤ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ GNU_ਸਰੋਤ /* activate extra prototypes for glibc */
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h> /* For CMSG_* */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LIMITS_H
# include <limits.h> /* For PATH_MAX, _POSIX_HOST_NAME_MAX */
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_BSTRING_H
# include <bstring.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ENDIAN_H
# include <endian.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_FCNTL_H
# include <fcntl.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_TTYENT_H
# include <ttyent.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_UTIME_H
# include <utime.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_MAILLOCK_H
# include <maillock.h> /* For _PATH_MAILDIR */
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ਅਗਲਾ
# include <libc.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_PATHS_H
# include <paths.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_FCNTL_H
# include <fcntl.h> /* For AT_FDCWD */
#ਜੇ_ਅੰਤ

/*
 *-*-nto-qnx needs these headers for strcasecmp and LASTLOG_FILE respectively
 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ਲੜੀਆਂ_H
# include <strings.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_H
# include <login.h>
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_UTMP_H
#  include <utmp.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_UTMPX_H
#  include <utmpx.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LASTLOG_H
#  include <lastlog.h>
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_SELECT_H
# include <sys/select.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_BSDTTY_H
# include <sys/bsdtty.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STDINT_H
# include <stdint.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ <termios.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_BITYPES_H
# include <sys/bitypes.h> /* For u_intXX_t */
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_CDEFS_H
# include <sys/cdefs.h> /* For __P() */
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_STAT_H
# include <sys/stat.h> /* For S_* constants and macros */
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h> /* For MIN, MAX, etc */
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_ਸਮਾਂ_H
# include <sys/time.h> /* for timespeccmp if present */
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_MMAN_H
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/mman.h> /* for MAP_ANONYMOUS */
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_STRTIO_H
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/strtio.h>	/* for TIOCCBRK on HP-UX */
#ਜੇ_ਅੰਤ
#ਜੇ defined(HAVE_SYS_PTMS_H) && defined(HAVE_DEV_PTMX)
# ਜੇ defined(HAVE_SYS_ਧਾਰਾ_H)
#  include <sys/stream.h>	/* reqd for queue_t on Solaris 2.5.1 */
# endif
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/ptms.h>	/* for grantpt() and friends */
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in_systm.h> /* For typedefs */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_RPC_TYPES_H
# include <rpc/types.h> /* For INADDR_LOOPBACK */
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
#ਜੇ defined(HAVE_SECURITY_PAM_APPL_H)
# include <security/pam_appl.h>
#ਜਾਂਜੇ defined (HAVE_PAM_PAM_APPL_H)
# include <pam/pam_appl.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_READPASSPHRASE_H
# include <readpassphrase.h>
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_IA_H
# include <ia.h>
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_IAF_H
# include <iaf.h>
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_TMPDIR_H
# include <tmpdir.h>
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_BSD_LIBUTIL_H)
# include <bsd/libutil.h>
#ਜਾਂਜੇ defined(HAVE_LIBUTIL_H)
# include <libutil.h>
#ਜੇ_ਅੰਤ

#ਜੇ defined(KRB5) && defined(USE_AFS)
# include <krb5.h>
# include <kafs.h>
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_SYS_SYSLOG_H)
# include <sys/syslog.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>

/*
 * On HP-UX 11.11, shadow.h and prot.h provide conflicting declarations
 * of getspnam when _INCLUDE__STDC__ is defined, so we unset it here.
 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GETSPNAM_CONFLICTING_DEFS
# ifdef _INCLUDE__STDC__
#  undef _INCLUDE__STDC__
# endif
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/opensslv.h> /* For OPENSSL_VERSION_NUMBER */
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "defines.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "platform.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openbsd-compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/bsd-nextstep.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "entropy.h"

#ਜੇ_ਅੰਤ /* INCLUDES_H */
