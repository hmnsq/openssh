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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <pwd.h>

#ضمن <sys/socket.h>

#ضمن <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#ضمن "base64.h"
#ضمن "sigact.h"
#ضمن "readpassphrase.h"
#ضمن "vis.h"
#ضمن "getrrsetbyname.h"
#ضمن "sha1.h"
#ضمن "bsd-sha2.h"
#ضمن "md5.h"
#ضمن "blf.h"
#ضمن "fnmatch.h"

#ifndef __THROW
# אם defined __cplusplus
#  define __THROW throw()
# אחרת
#  define __THROW
# endif
#endif

#אם defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#endif

#ifndef HAVE_BASENAME
حرف *basename(ثابت حرف *path);
#endif

#ifndef HAVE_BINDRESVPORT_SA
صحيح bindresvport_sa(صحيح sd, بنية sockaddr *sa);
#endif

#ifndef HAVE_CLOSEFROM
فراغ closefrom(صحيح);
#endif

#אם defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
صحيح ftruncate(صحيح filedes, off_t length);
#endif

#ifndef HAVE_GETLINE
#ضمن <stdio.h>
ssize_t getline(حرف **, size_t *, FILE *);
#endif

#ifndef HAVE_GETPAGESIZE
صحيح getpagesize(فراغ);
#endif

#ifndef HAVE_GETCWD
حرف *getcwd(حرف *pt, size_t size);
#endif

#ifndef HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#define getexecpath(a, b) (-1)
#endif

#ifndef HAVE_KILLPG
صحيح killpg(pid_t, صحيح);
#endif

#אם defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
فراغ *memmem(ثابت فراغ *, size_t, ثابت فراغ *, size_t);
#endif

#ifndef HAVE_REALLOCARRAY
فراغ *reallocarray(فراغ *, size_t, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
فراغ *recallocarray(فراغ *, size_t, size_t, size_t);
#endif

#ifndef HAVE_RRESVPORT_AF
صحيح rresvport_af(صحيح *alport, sa_family_t af);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(حرف *dst, ثابت حرف *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(حرف *dst, ثابت حرف *src, size_t siz);
#endif

#ifndef HAVE_STRCASESTR
حرف *strcasestr(ثابت حرف *, ثابت حرف *);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(ثابت حرف *, size_t);
#endif

#ifndef HAVE_STRNDUP
حرف *strndup(ثابت حرف *s, size_t n);
#endif

#ifndef HAVE_SETENV
صحيح setenv(سجل ثابت حرف *name, سجل ثابت حرف *value, صحيح rewrite);
#endif

#ifndef HAVE_STRMODE
فراغ strmode(صحيح mode, حرف *p);
#endif

#ifndef HAVE_STRPTIME
#ضمن  <time.h>
حرف *strptime(ثابت حرف *buf, ثابت حرف *fmt, بنية tm *tm);
#endif

#אם !defined(HAVE_MKDTEMP)
صحيح mkstemps(حرف *path, صحيح slen);
صحيح mkstemp(حرف *path);
حرف *mkdtemp(حرف *path);
#endif

#define mkstemp(x) _ssh_mkstemp(x)
صحيح _ssh_mkstemp(حرف *);

#ifndef HAVE_DAEMON
صحيح daemon(صحيح nochdir, صحيح noclose);
#endif

#ifndef HAVE_DIRNAME
حرف *dirname(ثابت حرف *path);
#endif

#ifndef HAVE_FMT_SCALED
#define	FMT_SCALED_STRSIZE	7
صحيح	fmt_scaled(long long number, حرف *result);
#endif

#ifndef HAVE_SCAN_SCALED
صحيح	scan_scaled(حرف *, long long *);
#endif

#אם defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
حرف *inet_ntoa(بنية in_addr in);
#endif

#ifndef HAVE_INET_NTOP
ثابت حرف *inet_ntop(صحيح af, ثابت فراغ *src, حرف *dst, socklen_t size);
#endif

#ifndef HAVE_INET_ATON
صحيح inet_aton(ثابت حرف *cp, بنية in_addr *addr);
#endif

#ifndef HAVE_STRSEP
حرف *strsep(حرف **stringp, ثابت حرف *delim);
#endif

#ifndef HAVE_SETPROCTITLE
فراغ setproctitle(ثابت حرف *fmt, ...);
فراغ compat_init_setproctitle(صحيح argc, حرف *argv[]);
#endif

#ifndef HAVE_GETGROUPLIST
صحيح getgrouplist(ثابت حرف *, gid_t, gid_t *, صحيح *);
#endif

#אם !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
صحيح BSDgetopt(صحيح argc, حرف * ثابت *argv, ثابت حرف *opts) __THROW;
#ضمن "openbsd-compat/getopt.h"
#endif

#אם ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# אם defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
صحيح readv(صحيح, بنية iovec *, صحيح);
# endif

# אם defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
صحيح writev(صحيح, بنية iovec *, صحيح);
# endif
#endif

/* Home grown routines */
#ضمن "bsd-signal.h"
#ضمن "bsd-misc.h"
#ضمن "bsd-setres_id.h"
#ضمن "bsd-statvfs.h"
#ضمن "bsd-waitpid.h"
#ضمن "bsd-poll.h"

#אם defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
صحيح getpeereid(صحيح , uid_t *, gid_t *);
#endif

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(فراغ);
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_ARC4RANDOM_BUF
فراغ arc4random_buf(فراغ *, size_t);
#endif

#ifndef HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#endif

#ifndef HAVE_ASPRINTF
صحيح asprintf(حرف **, ثابت حرف *, ...);
#endif

#ifndef HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
صحيح openpty(صحيح *, صحيح *, حرف *, ثابت بنية termios *,
    ثابت بنية winsize *);
#endif /* HAVE_OPENPTY */

#ifndef HAVE_SNPRINTF
صحيح snprintf(حرف *, size_t, SNPRINTF_CONST حرف *, ...);
#endif

#ifndef HAVE_STRTOLL
long long strtoll(ثابت حرف *, حرف **, صحيح);
#endif

#ifndef HAVE_STRTOUL
unsigned long strtoul(ثابت حرف *, حرف **, صحيح);
#endif

#ifndef HAVE_STRTOULL
unsigned long long strtoull(ثابت حرف *, حرف **, صحيح);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(ثابت حرف *, long long, long long, ثابت حرف **);
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
صحيح mbtowc(wchar_t *, ثابت حرف*, size_t);
#endif

#אם !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
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
# אחרת
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  אחרת
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#endif

#ifndef HAVE_VASPRINTF
صحيح vasprintf(حرف **, ثابت حرف *, va_list);
#endif

#ifndef HAVE_VSNPRINTF
صحيح vsnprintf(حرف *, size_t, ثابت حرف *, va_list);
#endif

#ifndef HAVE_USER_FROM_UID
حرف *user_from_uid(uid_t, صحيح);
#endif

#ifndef HAVE_GROUP_FROM_GID
حرف *group_from_gid(gid_t, صحيح);
#endif

#ifndef HAVE_TIMINGSAFE_BCMP
صحيح timingsafe_bcmp(ثابت فراغ *, ثابت فراغ *, size_t);
#endif

#ifndef HAVE_BCRYPT_PBKDF
صحيح	bcrypt_pbkdf(ثابت حرف *, size_t, ثابت uint8_t *, size_t,
    uint8_t *, size_t, unsigned صحيح);
#endif

#ifndef HAVE_EXPLICIT_BZERO
فراغ explicit_bzero(فراغ *p, size_t n);
#endif

#ifndef HAVE_FREEZERO
فراغ freezero(فراغ *, size_t);
#endif

#ifndef HAVE_LOCALTIME_R
بنية tm *localtime_r(ثابت time_t *, بنية tm *);
#endif

#ifndef HAVE_TIMEGM
#ضمن <time.h>
time_t timegm(بنية tm *);
#endif

حرف *xcrypt(ثابت حرف *password, ثابت حرف *salt);
حرف *shadow_pw(بنية passwd *pw);

/* rfc2553 socket API replacements */
#ضمن "fake-rfc2553.h"

/* Routines for a single OS platform */
#ضمن "bsd-cygwin_util.h"

#ضمن "port-aix.h"
#ضمن "port-irix.h"
#ضمن "port-linux.h"
#ضمن "port-solaris.h"
#ضمن "port-net.h"
#ضمن "port-uw.h"

/* _FORTIFY_SOURCE breaks FD_ISSET(n)/FD_SET(n) for n > FD_SETSIZE. Avoid. */
#אם defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# אם defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  אם __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, set)	kludge_FD_SET(n, set)
#   define FD_ISSET(n, set)	kludge_FD_ISSET(n, set)
فراغ kludge_FD_SET(صحيح, fd_set *);
صحيح kludge_FD_ISSET(صحيح, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#endif /* _OPENBSD_COMPAT_H */
