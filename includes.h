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

#నిర్వచితం_కాకపోతే INCLUDES_H
#నిర్వచించు INCLUDES_H

#అన్తర్భావ "config.h"

#నిర్వచితం_కాకపోతే GNU_ఆధారం
#నిర్వచించు GNU_ఆధారం /* activate extra prototypes for glibc */
#అయితే_ముగింపు

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h> /* For CMSG_* */

#నిర్వచితమైతే HAVE_LIMITS_H
# include <limits.h> /* For PATH_MAX, _POSIX_HOST_NAME_MAX */
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_BSTRING_H
# include <bstring.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_ENDIAN_H
# include <endian.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_FCNTL_H
# include <fcntl.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_TTYENT_H
# include <ttyent.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_UTIME_H
# include <utime.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_MAILLOCK_H
# include <maillock.h> /* For _PATH_MAILDIR */
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_తదుపరి
# include <libc.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_PATHS_H
# include <paths.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_FCNTL_H
# include <fcntl.h> /* For AT_FDCWD */
#అయితే_ముగింపు

/*
 *-*-nto-qnx needs these headers for strcasecmp and LASTLOG_FILE respectively
 */
#నిర్వచితమైతే HAVE_అక్షరశ్రేణులు_H
# include <strings.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_LOGIN_H
# include <login.h>
#అయితే_ముగింపు

#నిర్వచితమైతే HAVE_UTMP_H
#  include <utmp.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_UTMPX_H
#  include <utmpx.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_LASTLOG_H
#  include <lastlog.h>
#అయితే_ముగింపు

#నిర్వచితమైతే HAVE_SYS_SELECT_H
# include <sys/select.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_SYS_BSDTTY_H
# include <sys/bsdtty.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_STDINT_H
# include <stdint.h>
#అయితే_ముగింపు
#అన్తర్భావ <termios.h>
#నిర్వచితమైతే HAVE_SYS_BITYPES_H
# include <sys/bitypes.h> /* For u_intXX_t */
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_SYS_CDEFS_H
# include <sys/cdefs.h> /* For __P() */
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_SYS_STAT_H
# include <sys/stat.h> /* For S_* constants and macros */
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h> /* For MIN, MAX, etc */
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_SYS_సమయం_H
# include <sys/time.h> /* for timespeccmp if present */
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_SYS_MMAN_H
#అన్తర్భావ <sys/mman.h> /* for MAP_ANONYMOUS */
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_SYS_STRTIO_H
#అన్తర్భావ <sys/strtio.h>	/* for TIOCCBRK on HP-UX */
#అయితే_ముగింపు
#ఒకవేళ defined(HAVE_SYS_PTMS_H) && defined(HAVE_DEV_PTMX)
# ఒకవేళ defined(HAVE_SYS_ప్రవాహం_H)
#  include <sys/stream.h>	/* reqd for queue_t on Solaris 2.5.1 */
# endif
#అన్తర్భావ <sys/ptms.h>	/* for grantpt() and friends */
#అయితే_ముగింపు

#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <netinet/in_systm.h> /* For typedefs */
#నిర్వచితమైతే HAVE_RPC_TYPES_H
# include <rpc/types.h> /* For INADDR_LOOPBACK */
#అయితే_ముగింపు
#నిర్వచితమైతే USE_PAM
#ఒకవేళ defined(HAVE_SECURITY_PAM_APPL_H)
# include <security/pam_appl.h>
#లేదావేళ defined (HAVE_PAM_PAM_APPL_H)
# include <pam/pam_appl.h>
#అయితే_ముగింపు
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_READPASSPHRASE_H
# include <readpassphrase.h>
#అయితే_ముగింపు

#నిర్వచితమైతే HAVE_IA_H
# include <ia.h>
#అయితే_ముగింపు

#నిర్వచితమైతే HAVE_IAF_H
# include <iaf.h>
#అయితే_ముగింపు

#నిర్వచితమైతే HAVE_TMPDIR_H
# include <tmpdir.h>
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_BSD_LIBUTIL_H)
# include <bsd/libutil.h>
#లేదావేళ defined(HAVE_LIBUTIL_H)
# include <libutil.h>
#అయితే_ముగింపు

#ఒకవేళ defined(KRB5) && defined(USE_AFS)
# include <krb5.h>
# include <kafs.h>
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_SYS_SYSLOG_H)
# include <sys/syslog.h>
#అయితే_ముగింపు

#అన్తర్భావ <errno.h>

/*
 * On HP-UX 11.11, shadow.h and prot.h provide conflicting declarations
 * of getspnam when _INCLUDE__STDC__ is defined, so we unset it here.
 */
#నిర్వచితమైతే GETSPNAM_CONFLICTING_DEFS
# ifdef _INCLUDE__STDC__
#  undef _INCLUDE__STDC__
# endif
#అయితే_ముగింపు

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/opensslv.h> /* For OPENSSL_VERSION_NUMBER */
#అయితే_ముగింపు

#అన్తర్భావ "defines.h"

#అన్తర్భావ "platform.h"
#అన్తర్భావ "openbsd-compat/openbsd-compat.h"
#అన్తర్భావ "openbsd-compat/bsd-nextstep.h"

#అన్తర్భావ "entropy.h"

#అయితే_ముగింపు /* INCLUDES_H */
