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

#که_نه_تعریف_شوی INCLUDES_H
#تعریف_کړه INCLUDES_H

#ضمن "config.h"

#که_نه_تعریف_شوی GNU_سرچینه
#تعریف_کړه GNU_سرچینه /* activate extra prototypes for glibc */
#د_که_پای

#ضمن <sys/types.h>
#ضمن <sys/socket.h> /* For CMSG_* */

#که_تعریف_شوی HAVE_LIMITS_H
# include <limits.h> /* For PATH_MAX, _POSIX_HOST_NAME_MAX */
#د_که_پای
#که_تعریف_شوی HAVE_BSTRING_H
# include <bstring.h>
#د_که_پای
#که_تعریف_شوی HAVE_ENDIAN_H
# include <endian.h>
#د_که_پای
#که_تعریف_شوی HAVE_FCNTL_H
# include <fcntl.h>
#د_که_پای
#که_تعریف_شوی HAVE_TTYENT_H
# include <ttyent.h>
#د_که_پای
#که_تعریف_شوی HAVE_UTIME_H
# include <utime.h>
#د_که_پای
#که_تعریف_شوی HAVE_MAILLOCK_H
# include <maillock.h> /* For _PATH_MAILDIR */
#د_که_پای
#که_تعریف_شوی HAVE_بل
# include <libc.h>
#د_که_پای
#که_تعریف_شوی HAVE_PATHS_H
# include <paths.h>
#د_که_پای
#که_تعریف_شوی HAVE_FCNTL_H
# include <fcntl.h> /* For AT_FDCWD */
#د_که_پای

/*
 *-*-nto-qnx needs these headers for strcasecmp and LASTLOG_FILE respectively
 */
#که_تعریف_شوی HAVE_مزي_ګانې_H
# include <strings.h>
#د_که_پای
#که_تعریف_شوی HAVE_LOGIN_H
# include <login.h>
#د_که_پای

#که_تعریف_شوی HAVE_UTMP_H
#  include <utmp.h>
#د_که_پای
#که_تعریف_شوی HAVE_UTMPX_H
#  include <utmpx.h>
#د_که_پای
#که_تعریف_شوی HAVE_LASTLOG_H
#  include <lastlog.h>
#د_که_پای

#که_تعریف_شوی HAVE_SYS_SELECT_H
# include <sys/select.h>
#د_که_پای
#که_تعریف_شوی HAVE_SYS_BSDTTY_H
# include <sys/bsdtty.h>
#د_که_پای
#که_تعریف_شوی HAVE_STDINT_H
# include <stdint.h>
#د_که_پای
#ضمن <termios.h>
#که_تعریف_شوی HAVE_SYS_BITYPES_H
# include <sys/bitypes.h> /* For u_intXX_t */
#د_که_پای
#که_تعریف_شوی HAVE_SYS_CDEFS_H
# include <sys/cdefs.h> /* For __P() */
#د_که_پای
#که_تعریف_شوی HAVE_SYS_STAT_H
# include <sys/stat.h> /* For S_* constants and macros */
#د_که_پای
#که_تعریف_شوی HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h> /* For MIN, MAX, etc */
#د_که_پای
#که_تعریف_شوی HAVE_SYS_وخت_H
# include <sys/time.h> /* for timespeccmp if present */
#د_که_پای
#که_تعریف_شوی HAVE_SYS_MMAN_H
#ضمن <sys/mman.h> /* for MAP_ANONYMOUS */
#د_که_پای
#که_تعریف_شوی HAVE_SYS_STRTIO_H
#ضمن <sys/strtio.h>	/* for TIOCCBRK on HP-UX */
#د_که_پای
#إذا defined(HAVE_SYS_PTMS_H) && defined(HAVE_DEV_PTMX)
# إذا defined(HAVE_SYS_بهیر_H)
#  include <sys/stream.h>	/* reqd for queue_t on Solaris 2.5.1 */
# endif
#ضمن <sys/ptms.h>	/* for grantpt() and friends */
#د_که_پای

#ضمن <netinet/in.h>
#ضمن <netinet/in_systm.h> /* For typedefs */
#که_تعریف_شوی HAVE_RPC_TYPES_H
# include <rpc/types.h> /* For INADDR_LOOPBACK */
#د_که_پای
#که_تعریف_شوی USE_PAM
#إذا defined(HAVE_SECURITY_PAM_APPL_H)
# include <security/pam_appl.h>
#وإلاإذا defined (HAVE_PAM_PAM_APPL_H)
# include <pam/pam_appl.h>
#د_که_پای
#د_که_پای
#که_تعریف_شوی HAVE_READPASSPHRASE_H
# include <readpassphrase.h>
#د_که_پای

#که_تعریف_شوی HAVE_IA_H
# include <ia.h>
#د_که_پای

#که_تعریف_شوی HAVE_IAF_H
# include <iaf.h>
#د_که_پای

#که_تعریف_شوی HAVE_TMPDIR_H
# include <tmpdir.h>
#د_که_پای

#إذا defined(HAVE_BSD_LIBUTIL_H)
# include <bsd/libutil.h>
#وإلاإذا defined(HAVE_LIBUTIL_H)
# include <libutil.h>
#د_که_پای

#إذا defined(KRB5) && defined(USE_AFS)
# include <krb5.h>
# include <kafs.h>
#د_که_پای

#إذا defined(HAVE_SYS_SYSLOG_H)
# include <sys/syslog.h>
#د_که_پای

#ضمن <errno.h>

/*
 * On HP-UX 11.11, shadow.h and prot.h provide conflicting declarations
 * of getspnam when _INCLUDE__STDC__ is defined, so we unset it here.
 */
#که_تعریف_شوی GETSPNAM_CONFLICTING_DEFS
# ifdef _INCLUDE__STDC__
#  undef _INCLUDE__STDC__
# endif
#د_که_پای

#که_تعریف_شوی WITH_OPENSSL
#ضمن <openssl/opensslv.h> /* For OPENSSL_VERSION_NUMBER */
#د_که_پای

#ضمن "defines.h"

#ضمن "platform.h"
#ضمن "openbsd-compat/openbsd-compat.h"
#ضمن "openbsd-compat/bsd-nextstep.h"

#ضمن "entropy.h"

#د_که_پای /* INCLUDES_H */
