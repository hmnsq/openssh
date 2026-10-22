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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ INCLUDES_H
#ವ್ಯಾಖ್ಯಾನಿಸು INCLUDES_H

#ಅನ್ತರ್ಭಾವ "config.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ GNU_ಮೂಲ
#ವ್ಯಾಖ್ಯಾನಿಸು GNU_ಮೂಲ /* activate extra prototypes for glibc */
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h> /* For CMSG_* */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LIMITS_H
# include <limits.h> /* For PATH_MAX, _POSIX_HOST_NAME_MAX */
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_BSTRING_H
# include <bstring.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ENDIAN_H
# include <endian.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FCNTL_H
# include <fcntl.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_TTYENT_H
# include <ttyent.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_UTIME_H
# include <utime.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_MAILLOCK_H
# include <maillock.h> /* For _PATH_MAILDIR */
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ಮುಂದಿನ
# include <libc.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_PATHS_H
# include <paths.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FCNTL_H
# include <fcntl.h> /* For AT_FDCWD */
#ಆದರೆ_ಅಂತ್ಯ

/*
 *-*-nto-qnx needs these headers for strcasecmp and LASTLOG_FILE respectively
 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ಅಕ್ಷರಸರಣಿಗಳು_H
# include <strings.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_H
# include <login.h>
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_UTMP_H
#  include <utmp.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_UTMPX_H
#  include <utmpx.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LASTLOG_H
#  include <lastlog.h>
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_SELECT_H
# include <sys/select.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_BSDTTY_H
# include <sys/bsdtty.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STDINT_H
# include <stdint.h>
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ <termios.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_BITYPES_H
# include <sys/bitypes.h> /* For u_intXX_t */
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_CDEFS_H
# include <sys/cdefs.h> /* For __P() */
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_STAT_H
# include <sys/stat.h> /* For S_* constants and macros */
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h> /* For MIN, MAX, etc */
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_ಸಮಯ_H
# include <sys/time.h> /* for timespeccmp if present */
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_MMAN_H
#ಅನ್ತರ್ಭಾವ <sys/mman.h> /* for MAP_ANONYMOUS */
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_STRTIO_H
#ಅನ್ತರ್ಭಾವ <sys/strtio.h>	/* for TIOCCBRK on HP-UX */
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(HAVE_SYS_PTMS_H) && defined(HAVE_DEV_PTMX)
# ಆದರೆ defined(HAVE_SYS_ಹರಿವು_H)
#  include <sys/stream.h>	/* reqd for queue_t on Solaris 2.5.1 */
# endif
#ಅನ್ತರ್ಭಾವ <sys/ptms.h>	/* for grantpt() and friends */
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <netinet/in_systm.h> /* For typedefs */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_RPC_TYPES_H
# include <rpc/types.h> /* For INADDR_LOOPBACK */
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
#ಆದರೆ defined(HAVE_SECURITY_PAM_APPL_H)
# include <security/pam_appl.h>
#ಅಥವಾಆದರೆ defined (HAVE_PAM_PAM_APPL_H)
# include <pam/pam_appl.h>
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_READPASSPHRASE_H
# include <readpassphrase.h>
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_IA_H
# include <ia.h>
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_IAF_H
# include <iaf.h>
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_TMPDIR_H
# include <tmpdir.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_BSD_LIBUTIL_H)
# include <bsd/libutil.h>
#ಅಥವಾಆದರೆ defined(HAVE_LIBUTIL_H)
# include <libutil.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(KRB5) && defined(USE_AFS)
# include <krb5.h>
# include <kafs.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_SYS_SYSLOG_H)
# include <sys/syslog.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ <errno.h>

/*
 * On HP-UX 11.11, shadow.h and prot.h provide conflicting declarations
 * of getspnam when _INCLUDE__STDC__ is defined, so we unset it here.
 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GETSPNAM_CONFLICTING_DEFS
# ifdef _INCLUDE__STDC__
#  undef _INCLUDE__STDC__
# endif
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/opensslv.h> /* For OPENSSL_VERSION_NUMBER */
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "defines.h"

#ಅನ್ತರ್ಭಾವ "platform.h"
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openbsd-compat.h"
#ಅನ್ತರ್ಭಾವ "openbsd-compat/bsd-nextstep.h"

#ಅನ್ತರ್ಭಾವ "entropy.h"

#ಆದರೆ_ಅಂತ್ಯ /* INCLUDES_H */
