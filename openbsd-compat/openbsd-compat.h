/*
 * Copyright (c) 1999-2003 Damien Miller.  All rights reserved.
 * Copyright (c) 2003 Ben Lindstrom. All rights reserved.
 * Copyright (c) 2002 Tim Rice.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _OPENBSD_COMPAT_H
#define _OPENBSD_COMPAT_H

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>

#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ಅನ್ತರ್ಭಾವ <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#ಅನ್ತರ್ಭಾವ "base64.h"
#ಅನ್ತರ್ಭಾವ "sigact.h"
#ಅನ್ತರ್ಭಾವ "readpassphrase.h"
#ಅನ್ತರ್ಭಾವ "vis.h"
#ಅನ್ತರ್ಭಾವ "getrrsetbyname.h"
#ಅನ್ತರ್ಭಾವ "sha1.h"
#ಅನ್ತರ್ಭಾವ "bsd-sha2.h"
#ಅನ್ತರ್ಭಾವ "md5.h"
#ಅನ್ತರ್ಭಾವ "blf.h"
#ಅನ್ತರ್ಭಾವ "fnmatch.h"

#ifndef __THROW
# ಯದಿ defined __cplusplus
#  define __THROW throw()
# ಅನ್ಯಥಾ
#  define __THROW
# endif
#endif

#ಯದಿ defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#endif

#ifndef HAVE_BASENAME
ವರ್ಣ *basename(ಧ್ರುವ ವರ್ಣ *path);
#endif

#ifndef HAVE_BINDRESVPORT_SA
ಪೂರ್ಣಾಙ್ಕ bindresvport_sa(ಪೂರ್ಣಾಙ್ಕ sd, ಸಂರಚನಾ sockaddr *sa);
#endif

#ifndef HAVE_CLOSEFROM
ಶೂನ್ಯ closefrom(ಪೂರ್ಣಾಙ್ಕ);
#endif

#ಯದಿ defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
ಪೂರ್ಣಾಙ್ಕ ftruncate(ಪೂರ್ಣಾಙ್ಕ filedes, off_t length);
#endif

#ifndef HAVE_GETLINE
#ಅನ್ತರ್ಭಾವ <stdio.h>
ssize_t getline(ವರ್ಣ **, size_t *, FILE *);
#endif

#ifndef HAVE_GETPAGESIZE
ಪೂರ್ಣಾಙ್ಕ getpagesize(ಶೂನ್ಯ);
#endif

#ifndef HAVE_GETCWD
ವರ್ಣ *getcwd(ವರ್ಣ *pt, size_t size);
#endif

#ifndef HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#define getexecpath(a, b) (-1)
#endif

#ifndef HAVE_KILLPG
ಪೂರ್ಣಾಙ್ಕ killpg(pid_t, ಪೂರ್ಣಾಙ್ಕ);
#endif

#ಯದಿ defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
ಶೂನ್ಯ *memmem(ಧ್ರುವ ಶೂನ್ಯ *, size_t, ಧ್ರುವ ಶೂನ್ಯ *, size_t);
#endif

#ifndef HAVE_REALLOCARRAY
ಶೂನ್ಯ *reallocarray(ಶೂನ್ಯ *, size_t, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
ಶೂನ್ಯ *recallocarray(ಶೂನ್ಯ *, size_t, size_t, size_t);
#endif

#ifndef HAVE_RRESVPORT_AF
ಪೂರ್ಣಾಙ್ಕ rresvport_af(ಪೂರ್ಣಾಙ್ಕ *alport, sa_family_t af);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(ವರ್ಣ *dst, ಧ್ರುವ ವರ್ಣ *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(ವರ್ಣ *dst, ಧ್ರುವ ವರ್ಣ *src, size_t siz);
#endif

#ifndef HAVE_STRCASESTR
ವರ್ಣ *strcasestr(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(ಧ್ರುವ ವರ್ಣ *, size_t);
#endif

#ifndef HAVE_STRNDUP
ವರ್ಣ *strndup(ಧ್ರುವ ವರ್ಣ *s, size_t n);
#endif

#ifndef HAVE_SETENV
ಪೂರ್ಣಾಙ್ಕ setenv(ಪಞ್ಜಿಕಾ ಧ್ರುವ ವರ್ಣ *name, ಪಞ್ಜಿಕಾ ಧ್ರುವ ವರ್ಣ *ಮೌಲ್ಯ, ಪೂರ್ಣಾಙ್ಕ rewrite);
#endif

#ifndef HAVE_STRMODE
ಶೂನ್ಯ strmode(ಪೂರ್ಣಾಙ್ಕ mode, ವರ್ಣ *p);
#endif

#ifndef HAVE_STRPTIME
#ಅನ್ತರ್ಭಾವ  <time.h>
ವರ್ಣ *strptime(ಧ್ರುವ ವರ್ಣ *buf, ಧ್ರುವ ವರ್ಣ *fmt, ಸಂರಚನಾ tm *tm);
#endif

#ಯದಿ !defined(HAVE_MKDTEMP)
ಪೂರ್ಣಾಙ್ಕ mkstemps(ವರ್ಣ *path, ಪೂರ್ಣಾಙ್ಕ slen);
ಪೂರ್ಣಾಙ್ಕ mkstemp(ವರ್ಣ *path);
ವರ್ಣ *mkdtemp(ವರ್ಣ *path);
#endif

#define mkstemp(x) _ssh_mkstemp(x)
ಪೂರ್ಣಾಙ್ಕ _ssh_mkstemp(ವರ್ಣ *);

#ifndef HAVE_DAEMON
ಪೂರ್ಣಾಙ್ಕ daemon(ಪೂರ್ಣಾಙ್ಕ nochdir, ಪೂರ್ಣಾಙ್ಕ noclose);
#endif

#ifndef HAVE_DIRNAME
ವರ್ಣ *dirname(ಧ್ರುವ ವರ್ಣ *path);
#endif

#ifndef HAVE_FMT_SCALED
#define	FMT_SCALED_STRSIZE	7
ಪೂರ್ಣಾಙ್ಕ	fmt_scaled(long long ಸಂಖ್ಯೆ, ವರ್ಣ *result);
#endif

#ifndef HAVE_SCAN_SCALED
ಪೂರ್ಣಾಙ್ಕ	scan_scaled(ವರ್ಣ *, long long *);
#endif

#ಯದಿ defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
ವರ್ಣ *inet_ntoa(ಸಂರಚನಾ in_addr in);
#endif

#ifndef HAVE_INET_NTOP
ಧ್ರುವ ವರ್ಣ *inet_ntop(ಪೂರ್ಣಾಙ್ಕ af, ಧ್ರುವ ಶೂನ್ಯ *src, ವರ್ಣ *dst, socklen_t size);
#endif

#ifndef HAVE_INET_ATON
ಪೂರ್ಣಾಙ್ಕ inet_aton(ಧ್ರುವ ವರ್ಣ *cp, ಸಂರಚನಾ in_addr *addr);
#endif

#ifndef HAVE_STRSEP
ವರ್ಣ *strsep(ವರ್ಣ **stringp, ಧ್ರುವ ವರ್ಣ *delim);
#endif

#ifndef HAVE_SETPROCTITLE
ಶೂನ್ಯ setproctitle(ಧ್ರುವ ವರ್ಣ *fmt, ...);
ಶೂನ್ಯ compat_init_setproctitle(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ *argv[]);
#endif

#ifndef HAVE_GETGROUPLIST
ಪೂರ್ಣಾಙ್ಕ getgrouplist(ಧ್ರುವ ವರ್ಣ *, gid_t, gid_t *, ಪೂರ್ಣಾಙ್ಕ *);
#endif

#ಯದಿ !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
ಪೂರ್ಣಾಙ್ಕ BSDgetopt(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ * ಧ್ರುವ *argv, ಧ್ರುವ ವರ್ಣ *opts) __THROW;
#ಅನ್ತರ್ಭಾವ "openbsd-compat/getopt.h"
#endif

#ಯದಿ ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# ಯದಿ defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
ಪೂರ್ಣಾಙ್ಕ readv(ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ iovec *, ಪೂರ್ಣಾಙ್ಕ);
# endif

# ಯದಿ defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
ಪೂರ್ಣಾಙ್ಕ writev(ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ iovec *, ಪೂರ್ಣಾಙ್ಕ);
# endif
#endif

/* Home grown routines */
#ಅನ್ತರ್ಭಾವ "bsd-signal.h"
#ಅನ್ತರ್ಭಾವ "bsd-misc.h"
#ಅನ್ತರ್ಭಾವ "bsd-setres_id.h"
#ಅನ್ತರ್ಭಾವ "bsd-statvfs.h"
#ಅನ್ತರ್ಭಾವ "bsd-waitpid.h"
#ಅನ್ತರ್ಭಾವ "bsd-poll.h"

#ಯದಿ defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
ಪೂರ್ಣಾಙ್ಕ getpeereid(ಪೂರ್ಣಾಙ್ಕ , uid_t *, gid_t *);
#endif

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(ಶೂನ್ಯ);
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_ARC4RANDOM_BUF
ಶೂನ್ಯ arc4random_buf(ಶೂನ್ಯ *, size_t);
#endif

#ifndef HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#endif

#ifndef HAVE_ASPRINTF
ಪೂರ್ಣಾಙ್ಕ asprintf(ವರ್ಣ **, ಧ್ರುವ ವರ್ಣ *, ...);
#endif

#ifndef HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
ಪೂರ್ಣಾಙ್ಕ openpty(ಪೂರ್ಣಾಙ್ಕ *, ಪೂರ್ಣಾಙ್ಕ *, ವರ್ಣ *, ಧ್ರುವ ಸಂರಚನಾ termios *,
    ಧ್ರುವ ಸಂರಚನಾ winsize *);
#endif /* HAVE_OPENPTY */

#ifndef HAVE_SNPRINTF
ಪೂರ್ಣಾಙ್ಕ snprintf(ವರ್ಣ *, size_t, SNPRINTF_CONST ವರ್ಣ *, ...);
#endif

#ifndef HAVE_STRTOLL
long long strtoll(ಧ್ರುವ ವರ್ಣ *, ವರ್ಣ **, ಪೂರ್ಣಾಙ್ಕ);
#endif

#ifndef HAVE_STRTOUL
unsigned long strtoul(ಧ್ರುವ ವರ್ಣ *, ವರ್ಣ **, ಪೂರ್ಣಾಙ್ಕ);
#endif

#ifndef HAVE_STRTOULL
unsigned long long strtoull(ಧ್ರುವ ವರ್ಣ *, ವರ್ಣ **, ಪೂರ್ಣಾಙ್ಕ);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(ಧ್ರುವ ವರ್ಣ *, long long, long long, ಧ್ರುವ ವರ್ಣ **);
#endif

/* multibyte character support */
#ifndef HAVE_MBLEN
# define mblen(x, y)	(1)
#endif

#ifndef HAVE_WCWIDTH
# define wcwidth(x)	(((x) >= 0x20 && (x) <= 0x7e) ? 1 : -1)
/* force our no-op nl_langinfo and mbtowc */
# undef HAVE_NL_LANGINFO
# undef HAVE_MBTOWC
# undef HAVE_LANGINFO_H
#endif

#ifndef HAVE_NL_LANGINFO
# define nl_langinfo(x)	""
#endif

#ifndef HAVE_MBTOWC
ಪೂರ್ಣಾಙ್ಕ mbtowc(wchar_t *, ಧ್ರುವ ವರ್ಣ*, size_t);
#endif

#ಯದಿ !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
# include <stdarg.h>
#endif

/*
 * Some platforms unconditionally undefine va_copy() so we define VA_COPY()
 * instead.  This is known to be the case on at least some configurations of
 * AIX with the xlc compiler.
 */
#ifndef VA_COPY
# ifdef HAVE_VA_COPY
#  define VA_COPY(dest, src) va_copy(dest, src)
# ಅನ್ಯಥಾ
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  ಅನ್ಯಥಾ
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#endif

#ifndef HAVE_VASPRINTF
ಪೂರ್ಣಾಙ್ಕ vasprintf(ವರ್ಣ **, ಧ್ರುವ ವರ್ಣ *, va_list);
#endif

#ifndef HAVE_VSNPRINTF
ಪೂರ್ಣಾಙ್ಕ vsnprintf(ವರ್ಣ *, size_t, ಧ್ರುವ ವರ್ಣ *, va_list);
#endif

#ifndef HAVE_USER_FROM_UID
ವರ್ಣ *user_from_uid(uid_t, ಪೂರ್ಣಾಙ್ಕ);
#endif

#ifndef HAVE_GROUP_FROM_GID
ವರ್ಣ *group_from_gid(gid_t, ಪೂರ್ಣಾಙ್ಕ);
#endif

#ifndef HAVE_TIMINGSAFE_BCMP
ಪೂರ್ಣಾಙ್ಕ timingsafe_bcmp(ಧ್ರುವ ಶೂನ್ಯ *, ಧ್ರುವ ಶೂನ್ಯ *, size_t);
#endif

#ifndef HAVE_BCRYPT_PBKDF
ಪೂರ್ಣಾಙ್ಕ	bcrypt_pbkdf(ಧ್ರುವ ವರ್ಣ *, size_t, ಧ್ರುವ uint8_t *, size_t,
    uint8_t *, size_t, unsigned ಪೂರ್ಣಾಙ್ಕ);
#endif

#ifndef HAVE_EXPLICIT_BZERO
ಶೂನ್ಯ explicit_bzero(ಶೂನ್ಯ *p, size_t n);
#endif

#ifndef HAVE_FREEZERO
ಶೂನ್ಯ freezero(ಶೂನ್ಯ *, size_t);
#endif

#ifndef HAVE_LOCALTIME_R
ಸಂರಚನಾ tm *localtime_r(ಧ್ರುವ time_t *, ಸಂರಚನಾ tm *);
#endif

#ifndef HAVE_TIMEGM
#ಅನ್ತರ್ಭಾವ <time.h>
time_t timegm(ಸಂರಚನಾ tm *);
#endif

ವರ್ಣ *xcrypt(ಧ್ರುವ ವರ್ಣ *password, ಧ್ರುವ ವರ್ಣ *salt);
ವರ್ಣ *shadow_pw(ಸಂರಚನಾ passwd *pw);

/* rfc2553 socket API replacements */
#ಅನ್ತರ್ಭಾವ "fake-rfc2553.h"

/* Routines for a single OS platform */
#ಅನ್ತರ್ಭಾವ "bsd-cygwin_util.h"

#ಅನ್ತರ್ಭಾವ "port-aix.h"
#ಅನ್ತರ್ಭಾವ "port-irix.h"
#ಅನ್ತರ್ಭಾವ "port-linux.h"
#ಅನ್ತರ್ಭಾವ "port-solaris.h"
#ಅನ್ತರ್ಭಾವ "port-net.h"
#ಅನ್ತರ್ಭಾವ "port-uw.h"

/* _FORTIFY_SOURCE breaks FD_ISSET(n)/FD_SET(n) for n > FD_SETSIZE. Avoid. */
#ಯದಿ defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# ಯದಿ defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  ಯದಿ __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, set)	kludge_FD_SET(n, set)
#   define FD_ISSET(n, set)	kludge_FD_ISSET(n, set)
ಶೂನ್ಯ kludge_FD_SET(ಪೂರ್ಣಾಙ್ಕ, fd_set *);
ಪೂರ್ಣಾಙ್ಕ kludge_FD_ISSET(ಪೂರ್ಣಾಙ್ಕ, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#endif /* _OPENBSD_COMPAT_H */
