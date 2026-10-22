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

#अगर_अघोषित INCLUDES_H
#घोषणा INCLUDES_H

#समावेश "config.h"

#अगर_अघोषित _GNU_SOURCE
#घोषणा _GNU_SOURCE /* activate extra prototypes for glibc */
#पूर्ण_अगर

#समावेश <sys/types.h>
#समावेश <sys/socket.h> /* For CMSG_* */

#अगर_घोषित HAVE_LIMITS_H
# include <limits.h> /* For PATH_MAX, _POSIX_HOST_NAME_MAX */
#पूर्ण_अगर
#अगर_घोषित HAVE_BSTRING_H
# include <bstring.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_ENDIAN_H
# include <endian.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_FCNTL_H
# include <fcntl.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_TTYENT_H
# include <ttyent.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_UTIME_H
# include <utime.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_MAILLOCK_H
# include <maillock.h> /* For _PATH_MAILDIR */
#पूर्ण_अगर
#अगर_घोषित HAVE_अग्र
# include <libc.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_PATHS_H
# include <paths.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_FCNTL_H
# include <fcntl.h> /* For AT_FDCWD */
#पूर्ण_अगर

/*
 *-*-nto-qnx needs these headers for strcasecmp and LASTLOG_FILE respectively
 */
#अगर_घोषित HAVE_STRINGS_H
# include <strings.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_LOGIN_H
# include <login.h>
#पूर्ण_अगर

#अगर_घोषित HAVE_UTMP_H
#  include <utmp.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_UTMPX_H
#  include <utmpx.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_LASTLOG_H
#  include <lastlog.h>
#पूर्ण_अगर

#अगर_घोषित HAVE_SYS_SELECT_H
# include <sys/select.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_SYS_BSDTTY_H
# include <sys/bsdtty.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_STDINT_H
# include <stdint.h>
#पूर्ण_अगर
#समावेश <termios.h>
#अगर_घोषित HAVE_SYS_BITYPES_H
# include <sys/bitypes.h> /* For u_intXX_t */
#पूर्ण_अगर
#अगर_घोषित HAVE_SYS_CDEFS_H
# include <sys/cdefs.h> /* For __P() */
#पूर्ण_अगर
#अगर_घोषित HAVE_SYS_STAT_H
# include <sys/stat.h> /* For S_* constants and macros */
#पूर्ण_अगर
#अगर_घोषित HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h> /* For MIN, MAX, etc */
#पूर्ण_अगर
#अगर_घोषित HAVE_SYS_TIME_H
# include <sys/time.h> /* for timespeccmp if present */
#पूर्ण_अगर
#अगर_घोषित HAVE_SYS_MMAN_H
#समावेश <sys/mman.h> /* for MAP_ANONYMOUS */
#पूर्ण_अगर
#अगर_घोषित HAVE_SYS_STRTIO_H
#समावेश <sys/strtio.h>	/* for TIOCCBRK on HP-UX */
#पूर्ण_अगर
#अगर defined(HAVE_SYS_PTMS_H) && defined(HAVE_DEV_PTMX)
# अगर defined(HAVE_SYS_STREAM_H)
#  include <sys/stream.h>	/* reqd for queue_t on Solaris 2.5.1 */
# endif
#समावेश <sys/ptms.h>	/* for grantpt() and friends */
#पूर्ण_अगर

#समावेश <netinet/in.h>
#समावेश <netinet/in_systm.h> /* For typedefs */
#अगर_घोषित HAVE_RPC_TYPES_H
# include <rpc/types.h> /* For INADDR_LOOPBACK */
#पूर्ण_अगर
#अगर_घोषित USE_PAM
#अगर defined(HAVE_SECURITY_PAM_APPL_H)
# include <security/pam_appl.h>
#या_अगर defined (HAVE_PAM_PAM_APPL_H)
# include <pam/pam_appl.h>
#पूर्ण_अगर
#पूर्ण_अगर
#अगर_घोषित HAVE_READPASSPHRASE_H
# include <readpassphrase.h>
#पूर्ण_अगर

#अगर_घोषित HAVE_IA_H
# include <ia.h>
#पूर्ण_अगर

#अगर_घोषित HAVE_IAF_H
# include <iaf.h>
#पूर्ण_अगर

#अगर_घोषित HAVE_TMPDIR_H
# include <tmpdir.h>
#पूर्ण_अगर

#अगर defined(HAVE_BSD_LIBUTIL_H)
# include <bsd/libutil.h>
#या_अगर defined(HAVE_LIBUTIL_H)
# include <libutil.h>
#पूर्ण_अगर

#अगर defined(KRB5) && defined(USE_AFS)
# include <krb5.h>
# include <kafs.h>
#पूर्ण_अगर

#अगर defined(HAVE_SYS_SYSLOG_H)
# include <sys/syslog.h>
#पूर्ण_अगर

#समावेश <errno.h>

/*
 * On HP-UX 11.11, shadow.h and prot.h provide conflicting declarations
 * of getspnam when _INCLUDE__STDC__ is defined, so we unset it here.
 */
#अगर_घोषित GETSPNAM_CONFLICTING_DEFS
# ifdef _INCLUDE__STDC__
#  undef _INCLUDE__STDC__
# endif
#पूर्ण_अगर

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/opensslv.h> /* For OPENSSL_VERSION_NUMBER */
#पूर्ण_अगर

#समावेश "defines.h"

#समावेश "platform.h"
#समावेश "openbsd-compat/openbsd-compat.h"
#समावेश "openbsd-compat/bsd-nextstep.h"

#समावेश "entropy.h"

#पूर्ण_अगर /* INCLUDES_H */
