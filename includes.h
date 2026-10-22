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

#यदि_अपरिभाषितम् INCLUDES_H
#परिभाषय INCLUDES_H

#अन्तर्भाव "config.h"

#यदि_अपरिभाषितम् _GNU_SOURCE
#परिभाषय _GNU_SOURCE /* activate extra prototypes for glibc */
#यदि_अन्तः

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h> /* For CMSG_* */

#यदि_परिभाषितम् HAVE_LIMITS_H
# include <limits.h> /* For PATH_MAX, _POSIX_HOST_NAME_MAX */
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_BSTRING_H
# include <bstring.h>
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_ENDIAN_H
# include <endian.h>
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_FCNTL_H
# include <fcntl.h>
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_TTYENT_H
# include <ttyent.h>
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_UTIME_H
# include <utime.h>
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_MAILLOCK_H
# include <maillock.h> /* For _PATH_MAILDIR */
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_अग्र
# include <libc.h>
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_PATHS_H
# include <paths.h>
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_FCNTL_H
# include <fcntl.h> /* For AT_FDCWD */
#यदि_अन्तः

/*
 *-*-nto-qnx needs these headers for strcasecmp and LASTLOG_FILE respectively
 */
#यदि_परिभाषितम् HAVE_वाक्यानि_H
# include <strings.h>
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_LOGIN_H
# include <login.h>
#यदि_अन्तः

#यदि_परिभाषितम् HAVE_UTMP_H
#  include <utmp.h>
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_UTMPX_H
#  include <utmpx.h>
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_LASTLOG_H
#  include <lastlog.h>
#यदि_अन्तः

#यदि_परिभाषितम् HAVE_SYS_SELECT_H
# include <sys/select.h>
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_SYS_BSDTTY_H
# include <sys/bsdtty.h>
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_STDINT_H
# include <stdint.h>
#यदि_अन्तः
#अन्तर्भाव <termios.h>
#यदि_परिभाषितम् HAVE_SYS_BITYPES_H
# include <sys/bitypes.h> /* For u_intXX_t */
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_SYS_CDEFS_H
# include <sys/cdefs.h> /* For __P() */
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_SYS_STAT_H
# include <sys/stat.h> /* For S_* constants and macros */
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h> /* For MIN, MAX, etc */
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_SYS_TIME_H
# include <sys/time.h> /* for timespeccmp if present */
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_SYS_MMAN_H
#अन्तर्भाव <sys/mman.h> /* for MAP_ANONYMOUS */
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_SYS_STRTIO_H
#अन्तर्भाव <sys/strtio.h>	/* for TIOCCBRK on HP-UX */
#यदि_अन्तः
#यदि defined(HAVE_SYS_PTMS_H) && defined(HAVE_DEV_PTMX)
# यदि defined(HAVE_SYS_प्रवाहः_H)
#  include <sys/stream.h>	/* reqd for queue_t on Solaris 2.5.1 */
# endif
#अन्तर्भाव <sys/ptms.h>	/* for grantpt() and friends */
#यदि_अन्तः

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <netinet/in_systm.h> /* For typedefs */
#यदि_परिभाषितम् HAVE_RPC_TYPES_H
# include <rpc/types.h> /* For INADDR_LOOPBACK */
#यदि_अन्तः
#यदि_परिभाषितम् USE_PAM
#यदि defined(HAVE_SECURITY_PAM_APPL_H)
# include <security/pam_appl.h>
#नोचेद्यदि defined (HAVE_PAM_PAM_APPL_H)
# include <pam/pam_appl.h>
#यदि_अन्तः
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_READPASSPHRASE_H
# include <readpassphrase.h>
#यदि_अन्तः

#यदि_परिभाषितम् HAVE_IA_H
# include <ia.h>
#यदि_अन्तः

#यदि_परिभाषितम् HAVE_IAF_H
# include <iaf.h>
#यदि_अन्तः

#यदि_परिभाषितम् HAVE_TMPDIR_H
# include <tmpdir.h>
#यदि_अन्तः

#यदि defined(HAVE_BSD_LIBUTIL_H)
# include <bsd/libutil.h>
#नोचेद्यदि defined(HAVE_LIBUTIL_H)
# include <libutil.h>
#यदि_अन्तः

#यदि defined(KRB5) && defined(USE_AFS)
# include <krb5.h>
# include <kafs.h>
#यदि_अन्तः

#यदि defined(HAVE_SYS_SYSLOG_H)
# include <sys/syslog.h>
#यदि_अन्तः

#अन्तर्भाव <errno.h>

/*
 * On HP-UX 11.11, shadow.h and prot.h provide conflicting declarations
 * of getspnam when _INCLUDE__STDC__ is defined, so we unset it here.
 */
#यदि_परिभाषितम् GETSPNAM_CONFLICTING_DEFS
# ifdef _INCLUDE__STDC__
#  undef _INCLUDE__STDC__
# endif
#यदि_अन्तः

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव <openssl/opensslv.h> /* For OPENSSL_VERSION_NUMBER */
#यदि_अन्तः

#अन्तर्भाव "defines.h"

#अन्तर्भाव "platform.h"
#अन्तर्भाव "openbsd-compat/openbsd-compat.h"
#अन्तर्भाव "openbsd-compat/bsd-nextstep.h"

#अन्तर्भाव "entropy.h"

#यदि_अन्तः /* INCLUDES_H */
