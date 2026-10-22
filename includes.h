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

#جيڪڏهن_وصف_نه_ٿيل INCLUDES_H
#وصف_ڪريو INCLUDES_H

#ضمن "config.h"

#جيڪڏهن_وصف_نه_ٿيل GNU_ذريعو
#وصف_ڪريو GNU_ذريعو /* activate extra prototypes for glibc */
#جيڪڏهن_پورو

#ضمن <sys/types.h>
#ضمن <sys/socket.h> /* For CMSG_* */

#جيڪڏهن_وصف_ٿيل HAVE_LIMITS_H
# include <limits.h> /* For PATH_MAX, _POSIX_HOST_NAME_MAX */
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_BSTRING_H
# include <bstring.h>
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_ENDIAN_H
# include <endian.h>
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_FCNTL_H
# include <fcntl.h>
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_TTYENT_H
# include <ttyent.h>
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_UTIME_H
# include <utime.h>
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_MAILLOCK_H
# include <maillock.h> /* For _PATH_MAILDIR */
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_ايندڙ
# include <libc.h>
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_PATHS_H
# include <paths.h>
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_FCNTL_H
# include <fcntl.h> /* For AT_FDCWD */
#جيڪڏهن_پورو

/*
 *-*-nto-qnx needs these headers for strcasecmp and LASTLOG_FILE respectively
 */
#جيڪڏهن_وصف_ٿيل HAVE_لڙيون_H
# include <strings.h>
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_LOGIN_H
# include <login.h>
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل HAVE_UTMP_H
#  include <utmp.h>
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_UTMPX_H
#  include <utmpx.h>
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_LASTLOG_H
#  include <lastlog.h>
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل HAVE_SYS_SELECT_H
# include <sys/select.h>
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_SYS_BSDTTY_H
# include <sys/bsdtty.h>
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_STDINT_H
# include <stdint.h>
#جيڪڏهن_پورو
#ضمن <termios.h>
#جيڪڏهن_وصف_ٿيل HAVE_SYS_BITYPES_H
# include <sys/bitypes.h> /* For u_intXX_t */
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_SYS_CDEFS_H
# include <sys/cdefs.h> /* For __P() */
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_SYS_STAT_H
# include <sys/stat.h> /* For S_* constants and macros */
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h> /* For MIN, MAX, etc */
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_SYS_وقت_H
# include <sys/time.h> /* for timespeccmp if present */
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_SYS_MMAN_H
#ضمن <sys/mman.h> /* for MAP_ANONYMOUS */
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_SYS_STRTIO_H
#ضمن <sys/strtio.h>	/* for TIOCCBRK on HP-UX */
#جيڪڏهن_پورو
#إذا defined(HAVE_SYS_PTMS_H) && defined(HAVE_DEV_PTMX)
# إذا defined(HAVE_SYS_وهڪرو_H)
#  include <sys/stream.h>	/* reqd for queue_t on Solaris 2.5.1 */
# endif
#ضمن <sys/ptms.h>	/* for grantpt() and friends */
#جيڪڏهن_پورو

#ضمن <netinet/in.h>
#ضمن <netinet/in_systm.h> /* For typedefs */
#جيڪڏهن_وصف_ٿيل HAVE_RPC_TYPES_H
# include <rpc/types.h> /* For INADDR_LOOPBACK */
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل USE_PAM
#إذا defined(HAVE_SECURITY_PAM_APPL_H)
# include <security/pam_appl.h>
#وإلاإذا defined (HAVE_PAM_PAM_APPL_H)
# include <pam/pam_appl.h>
#جيڪڏهن_پورو
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_READPASSPHRASE_H
# include <readpassphrase.h>
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل HAVE_IA_H
# include <ia.h>
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل HAVE_IAF_H
# include <iaf.h>
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل HAVE_TMPDIR_H
# include <tmpdir.h>
#جيڪڏهن_پورو

#إذا defined(HAVE_BSD_LIBUTIL_H)
# include <bsd/libutil.h>
#وإلاإذا defined(HAVE_LIBUTIL_H)
# include <libutil.h>
#جيڪڏهن_پورو

#إذا defined(KRB5) && defined(USE_AFS)
# include <krb5.h>
# include <kafs.h>
#جيڪڏهن_پورو

#إذا defined(HAVE_SYS_SYSLOG_H)
# include <sys/syslog.h>
#جيڪڏهن_پورو

#ضمن <errno.h>

/*
 * On HP-UX 11.11, shadow.h and prot.h provide conflicting declarations
 * of getspnam when _INCLUDE__STDC__ is defined, so we unset it here.
 */
#جيڪڏهن_وصف_ٿيل GETSPNAM_CONFLICTING_DEFS
# ifdef _INCLUDE__STDC__
#  undef _INCLUDE__STDC__
# endif
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن <openssl/opensslv.h> /* For OPENSSL_VERSION_NUMBER */
#جيڪڏهن_پورو

#ضمن "defines.h"

#ضمن "platform.h"
#ضمن "openbsd-compat/openbsd-compat.h"
#ضمن "openbsd-compat/bsd-nextstep.h"

#ضمن "entropy.h"

#جيڪڏهن_پورو /* INCLUDES_H */
