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

#اگر_غیر_تعریف_شدہ INCLUDES_H
#تعریف_کرو INCLUDES_H

#شامل "config.h"

#اگر_غیر_تعریف_شدہ GNU_ماخذ
#تعریف_کرو GNU_ماخذ /* activate extra prototypes for glibc */
#اگر_ختم

#شامل <sys/types.h>
#شامل <sys/socket.h> /* For CMSG_* */

#اگر_تعریف_شدہ HAVE_LIMITS_H
# include <limits.h> /* For PATH_MAX, _POSIX_HOST_NAME_MAX */
#اگر_ختم
#اگر_تعریف_شدہ HAVE_BSTRING_H
# include <bstring.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_ENDIAN_H
# include <endian.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_FCNTL_H
# include <fcntl.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_TTYENT_H
# include <ttyent.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_UTIME_H
# include <utime.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_MAILLOCK_H
# include <maillock.h> /* For _PATH_MAILDIR */
#اگر_ختم
#اگر_تعریف_شدہ HAVE_اگلا
# include <libc.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_PATHS_H
# include <paths.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_FCNTL_H
# include <fcntl.h> /* For AT_FDCWD */
#اگر_ختم

/*
 *-*-nto-qnx needs these headers for strcasecmp and LASTLOG_FILE respectively
 */
#اگر_تعریف_شدہ HAVE_لڑیاں_H
# include <strings.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_LOGIN_H
# include <login.h>
#اگر_ختم

#اگر_تعریف_شدہ HAVE_UTMP_H
#  include <utmp.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_UTMPX_H
#  include <utmpx.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_LASTLOG_H
#  include <lastlog.h>
#اگر_ختم

#اگر_تعریف_شدہ HAVE_SYS_SELECT_H
# include <sys/select.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_SYS_BSDTTY_H
# include <sys/bsdtty.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_STDINT_H
# include <stdint.h>
#اگر_ختم
#شامل <termios.h>
#اگر_تعریف_شدہ HAVE_SYS_BITYPES_H
# include <sys/bitypes.h> /* For u_intXX_t */
#اگر_ختم
#اگر_تعریف_شدہ HAVE_SYS_CDEFS_H
# include <sys/cdefs.h> /* For __P() */
#اگر_ختم
#اگر_تعریف_شدہ HAVE_SYS_STAT_H
# include <sys/stat.h> /* For S_* constants and macros */
#اگر_ختم
#اگر_تعریف_شدہ HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h> /* For MIN, MAX, etc */
#اگر_ختم
#اگر_تعریف_شدہ HAVE_SYS_وقت_H
# include <sys/time.h> /* for timespeccmp if present */
#اگر_ختم
#اگر_تعریف_شدہ HAVE_SYS_MMAN_H
#شامل <sys/mman.h> /* for MAP_ANONYMOUS */
#اگر_ختم
#اگر_تعریف_شدہ HAVE_SYS_STRTIO_H
#شامل <sys/strtio.h>	/* for TIOCCBRK on HP-UX */
#اگر_ختم
#اگر defined(HAVE_SYS_PTMS_H) && defined(HAVE_DEV_PTMX)
# اگر defined(HAVE_SYS_دھارا_H)
#  include <sys/stream.h>	/* reqd for queue_t on Solaris 2.5.1 */
# endif
#شامل <sys/ptms.h>	/* for grantpt() and friends */
#اگر_ختم

#شامل <netinet/in.h>
#شامل <netinet/in_systm.h> /* For typedefs */
#اگر_تعریف_شدہ HAVE_RPC_TYPES_H
# include <rpc/types.h> /* For INADDR_LOOPBACK */
#اگر_ختم
#اگر_تعریف_شدہ USE_PAM
#اگر defined(HAVE_SECURITY_PAM_APPL_H)
# include <security/pam_appl.h>
#وگرنہ_اگر defined (HAVE_PAM_PAM_APPL_H)
# include <pam/pam_appl.h>
#اگر_ختم
#اگر_ختم
#اگر_تعریف_شدہ HAVE_READPASSPHRASE_H
# include <readpassphrase.h>
#اگر_ختم

#اگر_تعریف_شدہ HAVE_IA_H
# include <ia.h>
#اگر_ختم

#اگر_تعریف_شدہ HAVE_IAF_H
# include <iaf.h>
#اگر_ختم

#اگر_تعریف_شدہ HAVE_TMPDIR_H
# include <tmpdir.h>
#اگر_ختم

#اگر defined(HAVE_BSD_LIBUTIL_H)
# include <bsd/libutil.h>
#وگرنہ_اگر defined(HAVE_LIBUTIL_H)
# include <libutil.h>
#اگر_ختم

#اگر defined(KRB5) && defined(USE_AFS)
# include <krb5.h>
# include <kafs.h>
#اگر_ختم

#اگر defined(HAVE_SYS_SYSLOG_H)
# include <sys/syslog.h>
#اگر_ختم

#شامل <errno.h>

/*
 * On HP-UX 11.11, shadow.h and prot.h provide conflicting declarations
 * of getspnam when _INCLUDE__STDC__ is defined, so we unset it here.
 */
#اگر_تعریف_شدہ GETSPNAM_CONFLICTING_DEFS
# ifdef _INCLUDE__STDC__
#  undef _INCLUDE__STDC__
# endif
#اگر_ختم

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/opensslv.h> /* For OPENSSL_VERSION_NUMBER */
#اگر_ختم

#شامل "defines.h"

#شامل "platform.h"
#شامل "openbsd-compat/openbsd-compat.h"
#شامل "openbsd-compat/bsd-nextstep.h"

#شامل "entropy.h"

#اگر_ختم /* INCLUDES_H */
