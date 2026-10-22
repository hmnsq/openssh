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

#اگر_تعریف_نشده INCLUDES_H
#تعریف_کن INCLUDES_H

#ضمن "config.h"

#اگر_تعریف_نشده GNU_منبع
#تعریف_کن GNU_منبع /* activate extra prototypes for glibc */
#پایان_اگر

#ضمن <sys/types.h>
#ضمن <sys/socket.h> /* For CMSG_* */

#اگر_تعریف_شده HAVE_LIMITS_H
# include <limits.h> /* For PATH_MAX, _POSIX_HOST_NAME_MAX */
#پایان_اگر
#اگر_تعریف_شده HAVE_BSTRING_H
# include <bstring.h>
#پایان_اگر
#اگر_تعریف_شده HAVE_ENDIAN_H
# include <endian.h>
#پایان_اگر
#اگر_تعریف_شده HAVE_FCNTL_H
# include <fcntl.h>
#پایان_اگر
#اگر_تعریف_شده HAVE_TTYENT_H
# include <ttyent.h>
#پایان_اگر
#اگر_تعریف_شده HAVE_UTIME_H
# include <utime.h>
#پایان_اگر
#اگر_تعریف_شده HAVE_MAILLOCK_H
# include <maillock.h> /* For _PATH_MAILDIR */
#پایان_اگر
#اگر_تعریف_شده HAVE_بعدی
# include <libc.h>
#پایان_اگر
#اگر_تعریف_شده HAVE_PATHS_H
# include <paths.h>
#پایان_اگر
#اگر_تعریف_شده HAVE_FCNTL_H
# include <fcntl.h> /* For AT_FDCWD */
#پایان_اگر

/*
 *-*-nto-qnx needs these headers for strcasecmp and LASTLOG_FILE respectively
 */
#اگر_تعریف_شده HAVE_رشتهها_H
# include <strings.h>
#پایان_اگر
#اگر_تعریف_شده HAVE_LOGIN_H
# include <login.h>
#پایان_اگر

#اگر_تعریف_شده HAVE_UTMP_H
#  include <utmp.h>
#پایان_اگر
#اگر_تعریف_شده HAVE_UTMPX_H
#  include <utmpx.h>
#پایان_اگر
#اگر_تعریف_شده HAVE_LASTLOG_H
#  include <lastlog.h>
#پایان_اگر

#اگر_تعریف_شده HAVE_SYS_SELECT_H
# include <sys/select.h>
#پایان_اگر
#اگر_تعریف_شده HAVE_SYS_BSDTTY_H
# include <sys/bsdtty.h>
#پایان_اگر
#اگر_تعریف_شده HAVE_STDINT_H
# include <stdint.h>
#پایان_اگر
#ضمن <termios.h>
#اگر_تعریف_شده HAVE_SYS_BITYPES_H
# include <sys/bitypes.h> /* For u_intXX_t */
#پایان_اگر
#اگر_تعریف_شده HAVE_SYS_CDEFS_H
# include <sys/cdefs.h> /* For __P() */
#پایان_اگر
#اگر_تعریف_شده HAVE_SYS_STAT_H
# include <sys/stat.h> /* For S_* constants and macros */
#پایان_اگر
#اگر_تعریف_شده HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h> /* For MIN, MAX, etc */
#پایان_اگر
#اگر_تعریف_شده HAVE_SYS_زمان_H
# include <sys/time.h> /* for timespeccmp if present */
#پایان_اگر
#اگر_تعریف_شده HAVE_SYS_MMAN_H
#ضمن <sys/mman.h> /* for MAP_ANONYMOUS */
#پایان_اگر
#اگر_تعریف_شده HAVE_SYS_STRTIO_H
#ضمن <sys/strtio.h>	/* for TIOCCBRK on HP-UX */
#پایان_اگر
#إذا defined(HAVE_SYS_PTMS_H) && defined(HAVE_DEV_PTMX)
# إذا defined(HAVE_SYS_جریان_H)
#  include <sys/stream.h>	/* reqd for queue_t on Solaris 2.5.1 */
# endif
#ضمن <sys/ptms.h>	/* for grantpt() and friends */
#پایان_اگر

#ضمن <netinet/in.h>
#ضمن <netinet/in_systm.h> /* For typedefs */
#اگر_تعریف_شده HAVE_RPC_TYPES_H
# include <rpc/types.h> /* For INADDR_LOOPBACK */
#پایان_اگر
#اگر_تعریف_شده USE_PAM
#إذا defined(HAVE_SECURITY_PAM_APPL_H)
# include <security/pam_appl.h>
#وإلاإذا defined (HAVE_PAM_PAM_APPL_H)
# include <pam/pam_appl.h>
#پایان_اگر
#پایان_اگر
#اگر_تعریف_شده HAVE_READPASSPHRASE_H
# include <readpassphrase.h>
#پایان_اگر

#اگر_تعریف_شده HAVE_IA_H
# include <ia.h>
#پایان_اگر

#اگر_تعریف_شده HAVE_IAF_H
# include <iaf.h>
#پایان_اگر

#اگر_تعریف_شده HAVE_TMPDIR_H
# include <tmpdir.h>
#پایان_اگر

#إذا defined(HAVE_BSD_LIBUTIL_H)
# include <bsd/libutil.h>
#وإلاإذا defined(HAVE_LIBUTIL_H)
# include <libutil.h>
#پایان_اگر

#إذا defined(KRB5) && defined(USE_AFS)
# include <krb5.h>
# include <kafs.h>
#پایان_اگر

#إذا defined(HAVE_SYS_SYSLOG_H)
# include <sys/syslog.h>
#پایان_اگر

#ضمن <errno.h>

/*
 * On HP-UX 11.11, shadow.h and prot.h provide conflicting declarations
 * of getspnam when _INCLUDE__STDC__ is defined, so we unset it here.
 */
#اگر_تعریف_شده GETSPNAM_CONFLICTING_DEFS
# ifdef _INCLUDE__STDC__
#  undef _INCLUDE__STDC__
# endif
#پایان_اگر

#اگر_تعریف_شده WITH_OPENSSL
#ضمن <openssl/opensslv.h> /* For OPENSSL_VERSION_NUMBER */
#پایان_اگر

#ضمن "defines.h"

#ضمن "platform.h"
#ضمن "openbsd-compat/openbsd-compat.h"
#ضمن "openbsd-compat/bsd-nextstep.h"

#ضمن "entropy.h"

#پایان_اگر /* INCLUDES_H */
