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

#جے_بنا_تعریف INCLUDES_H
#تعریف_کرو INCLUDES_H

#ضمن "config.h"

#جے_بنا_تعریف GNU_سروت
#تعریف_کرو GNU_سروت /* activate extra prototypes for glibc */
#جے_انت

#ضمن <sys/types.h>
#ضمن <sys/socket.h> /* For CMSG_* */

#جے_تعریف_شدہ HAVE_LIMITS_H
# include <limits.h> /* For PATH_MAX, _POSIX_HOST_NAME_MAX */
#جے_انت
#جے_تعریف_شدہ HAVE_BSTRING_H
# include <bstring.h>
#جے_انت
#جے_تعریف_شدہ HAVE_ENDIAN_H
# include <endian.h>
#جے_انت
#جے_تعریف_شدہ HAVE_FCNTL_H
# include <fcntl.h>
#جے_انت
#جے_تعریف_شدہ HAVE_TTYENT_H
# include <ttyent.h>
#جے_انت
#جے_تعریف_شدہ HAVE_UTIME_H
# include <utime.h>
#جے_انت
#جے_تعریف_شدہ HAVE_MAILLOCK_H
# include <maillock.h> /* For _PATH_MAILDIR */
#جے_انت
#جے_تعریف_شدہ HAVE_اگلا
# include <libc.h>
#جے_انت
#جے_تعریف_شدہ HAVE_PATHS_H
# include <paths.h>
#جے_انت
#جے_تعریف_شدہ HAVE_FCNTL_H
# include <fcntl.h> /* For AT_FDCWD */
#جے_انت

/*
 *-*-nto-qnx needs these headers for strcasecmp and LASTLOG_FILE respectively
 */
#جے_تعریف_شدہ HAVE_لڑیاں_H
# include <strings.h>
#جے_انت
#جے_تعریف_شدہ HAVE_LOGIN_H
# include <login.h>
#جے_انت

#جے_تعریف_شدہ HAVE_UTMP_H
#  include <utmp.h>
#جے_انت
#جے_تعریف_شدہ HAVE_UTMPX_H
#  include <utmpx.h>
#جے_انت
#جے_تعریف_شدہ HAVE_LASTLOG_H
#  include <lastlog.h>
#جے_انت

#جے_تعریف_شدہ HAVE_SYS_SELECT_H
# include <sys/select.h>
#جے_انت
#جے_تعریف_شدہ HAVE_SYS_BSDTTY_H
# include <sys/bsdtty.h>
#جے_انت
#جے_تعریف_شدہ HAVE_STDINT_H
# include <stdint.h>
#جے_انت
#ضمن <termios.h>
#جے_تعریف_شدہ HAVE_SYS_BITYPES_H
# include <sys/bitypes.h> /* For u_intXX_t */
#جے_انت
#جے_تعریف_شدہ HAVE_SYS_CDEFS_H
# include <sys/cdefs.h> /* For __P() */
#جے_انت
#جے_تعریف_شدہ HAVE_SYS_STAT_H
# include <sys/stat.h> /* For S_* constants and macros */
#جے_انت
#جے_تعریف_شدہ HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h> /* For MIN, MAX, etc */
#جے_انت
#جے_تعریف_شدہ HAVE_SYS_ویلا_H
# include <sys/time.h> /* for timespeccmp if present */
#جے_انت
#جے_تعریف_شدہ HAVE_SYS_MMAN_H
#ضمن <sys/mman.h> /* for MAP_ANONYMOUS */
#جے_انت
#جے_تعریف_شدہ HAVE_SYS_STRTIO_H
#ضمن <sys/strtio.h>	/* for TIOCCBRK on HP-UX */
#جے_انت
#إذا defined(HAVE_SYS_PTMS_H) && defined(HAVE_DEV_PTMX)
# إذا defined(HAVE_SYS_دھارا_H)
#  include <sys/stream.h>	/* reqd for queue_t on Solaris 2.5.1 */
# endif
#ضمن <sys/ptms.h>	/* for grantpt() and friends */
#جے_انت

#ضمن <netinet/in.h>
#ضمن <netinet/in_systm.h> /* For typedefs */
#جے_تعریف_شدہ HAVE_RPC_TYPES_H
# include <rpc/types.h> /* For INADDR_LOOPBACK */
#جے_انت
#جے_تعریف_شدہ USE_PAM
#إذا defined(HAVE_SECURITY_PAM_APPL_H)
# include <security/pam_appl.h>
#وإلاإذا defined (HAVE_PAM_PAM_APPL_H)
# include <pam/pam_appl.h>
#جے_انت
#جے_انت
#جے_تعریف_شدہ HAVE_READPASSPHRASE_H
# include <readpassphrase.h>
#جے_انت

#جے_تعریف_شدہ HAVE_IA_H
# include <ia.h>
#جے_انت

#جے_تعریف_شدہ HAVE_IAF_H
# include <iaf.h>
#جے_انت

#جے_تعریف_شدہ HAVE_TMPDIR_H
# include <tmpdir.h>
#جے_انت

#إذا defined(HAVE_BSD_LIBUTIL_H)
# include <bsd/libutil.h>
#وإلاإذا defined(HAVE_LIBUTIL_H)
# include <libutil.h>
#جے_انت

#إذا defined(KRB5) && defined(USE_AFS)
# include <krb5.h>
# include <kafs.h>
#جے_انت

#إذا defined(HAVE_SYS_SYSLOG_H)
# include <sys/syslog.h>
#جے_انت

#ضمن <errno.h>

/*
 * On HP-UX 11.11, shadow.h and prot.h provide conflicting declarations
 * of getspnam when _INCLUDE__STDC__ is defined, so we unset it here.
 */
#جے_تعریف_شدہ GETSPNAM_CONFLICTING_DEFS
# ifdef _INCLUDE__STDC__
#  undef _INCLUDE__STDC__
# endif
#جے_انت

#جے_تعریف_شدہ WITH_OPENSSL
#ضمن <openssl/opensslv.h> /* For OPENSSL_VERSION_NUMBER */
#جے_انت

#ضمن "defines.h"

#ضمن "platform.h"
#ضمن "openbsd-compat/openbsd-compat.h"
#ضمن "openbsd-compat/bsd-nextstep.h"

#ضمن "entropy.h"

#جے_انت /* INCLUDES_H */
