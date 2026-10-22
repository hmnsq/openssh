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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <pwd.h>

#شامل <sys/socket.h>

#شامل <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#شامل "base64.h"
#شامل "sigact.h"
#شامل "readpassphrase.h"
#شامل "vis.h"
#شامل "getrrsetbyname.h"
#شامل "sha1.h"
#شامل "bsd-sha2.h"
#شامل "md5.h"
#شامل "blf.h"
#شامل "fnmatch.h"

#ifndef __THROW
# اگر defined __cplusplus
#  define __THROW throw()
# وگرنه
#  define __THROW
# endif
#endif

#اگر defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#endif

#ifndef HAVE_BASENAME
نویسه *basename(ثابت نویسه *path);
#endif

#ifndef HAVE_BINDRESVPORT_SA
صحیح bindresvport_sa(صحیح sd, ساختار sockaddr *sa);
#endif

#ifndef HAVE_CLOSEFROM
تهی closefrom(صحیح);
#endif

#اگر defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
صحیح ftruncate(صحیح filedes, off_t length);
#endif

#ifndef HAVE_GETLINE
#شامل <stdio.h>
ssize_t getline(نویسه **, size_t *, FILE *);
#endif

#ifndef HAVE_GETPAGESIZE
صحیح getpagesize(تهی);
#endif

#ifndef HAVE_GETCWD
نویسه *getcwd(نویسه *pt, size_t size);
#endif

#ifndef HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#define getexecpath(a, b) (-1)
#endif

#ifndef HAVE_KILLPG
صحیح killpg(pid_t, صحیح);
#endif

#اگر defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
تهی *memmem(ثابت تهی *, size_t, ثابت تهی *, size_t);
#endif

#ifndef HAVE_REALLOCARRAY
تهی *reallocarray(تهی *, size_t, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
تهی *recallocarray(تهی *, size_t, size_t, size_t);
#endif

#ifndef HAVE_RRESVPORT_AF
صحیح rresvport_af(صحیح *alport, sa_family_t af);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(نویسه *dst, ثابت نویسه *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(نویسه *dst, ثابت نویسه *src, size_t siz);
#endif

#ifndef HAVE_STRCASESTR
نویسه *strcasestr(ثابت نویسه *, ثابت نویسه *);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(ثابت نویسه *, size_t);
#endif

#ifndef HAVE_STRNDUP
نویسه *strndup(ثابت نویسه *s, size_t n);
#endif

#ifndef HAVE_SETENV
صحیح setenv(ثبات ثابت نویسه *name, ثبات ثابت نویسه *مقدار, صحیح rewrite);
#endif

#ifndef HAVE_STRMODE
تهی strmode(صحیح mode, نویسه *p);
#endif

#ifndef HAVE_STRPTIME
#شامل  <time.h>
نویسه *strptime(ثابت نویسه *buf, ثابت نویسه *fmt, ساختار tm *tm);
#endif

#اگر !defined(HAVE_MKDTEMP)
صحیح mkstemps(نویسه *path, صحیح slen);
صحیح mkstemp(نویسه *path);
نویسه *mkdtemp(نویسه *path);
#endif

#define mkstemp(x) _ssh_mkstemp(x)
صحیح _ssh_mkstemp(نویسه *);

#ifndef HAVE_DAEMON
صحیح daemon(صحیح nochdir, صحیح noclose);
#endif

#ifndef HAVE_DIRNAME
نویسه *dirname(ثابت نویسه *path);
#endif

#ifndef HAVE_FMT_SCALED
#define	FMT_SCALED_STRSIZE	7
صحیح	fmt_scaled(long long عدد, نویسه *result);
#endif

#ifndef HAVE_SCAN_SCALED
صحیح	scan_scaled(نویسه *, long long *);
#endif

#اگر defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
نویسه *inet_ntoa(ساختار in_addr in);
#endif

#ifndef HAVE_INET_NTOP
ثابت نویسه *inet_ntop(صحیح af, ثابت تهی *src, نویسه *dst, socklen_t size);
#endif

#ifndef HAVE_INET_ATON
صحیح inet_aton(ثابت نویسه *cp, ساختار in_addr *addr);
#endif

#ifndef HAVE_STRSEP
نویسه *strsep(نویسه **stringp, ثابت نویسه *delim);
#endif

#ifndef HAVE_SETPROCTITLE
تهی setproctitle(ثابت نویسه *fmt, ...);
تهی compat_init_setproctitle(صحیح argc, نویسه *argv[]);
#endif

#ifndef HAVE_GETGROUPLIST
صحیح getgrouplist(ثابت نویسه *, gid_t, gid_t *, صحیح *);
#endif

#اگر !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
صحیح BSDgetopt(صحیح argc, نویسه * ثابت *argv, ثابت نویسه *opts) __THROW;
#شامل "openbsd-compat/getopt.h"
#endif

#اگر ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# اگر defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
صحیح readv(صحیح, ساختار iovec *, صحیح);
# endif

# اگر defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
صحیح writev(صحیح, ساختار iovec *, صحیح);
# endif
#endif

/* Home grown routines */
#شامل "bsd-signal.h"
#شامل "bsd-misc.h"
#شامل "bsd-setres_id.h"
#شامل "bsd-statvfs.h"
#شامل "bsd-waitpid.h"
#شامل "bsd-poll.h"

#اگر defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
صحیح getpeereid(صحیح , uid_t *, gid_t *);
#endif

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(تهی);
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_ARC4RANDOM_BUF
تهی arc4random_buf(تهی *, size_t);
#endif

#ifndef HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#endif

#ifndef HAVE_ASPRINTF
صحیح asprintf(نویسه **, ثابت نویسه *, ...);
#endif

#ifndef HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
صحیح openpty(صحیح *, صحیح *, نویسه *, ثابت ساختار termios *,
    ثابت ساختار winsize *);
#endif /* HAVE_OPENPTY */

#ifndef HAVE_SNPRINTF
صحیح snprintf(نویسه *, size_t, SNPRINTF_CONST نویسه *, ...);
#endif

#ifndef HAVE_STRTOLL
long long strtoll(ثابت نویسه *, نویسه **, صحیح);
#endif

#ifndef HAVE_STRTOUL
unsigned long strtoul(ثابت نویسه *, نویسه **, صحیح);
#endif

#ifndef HAVE_STRTOULL
unsigned long long strtoull(ثابت نویسه *, نویسه **, صحیح);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(ثابت نویسه *, long long, long long, ثابت نویسه **);
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
صحیح mbtowc(wchar_t *, ثابت نویسه*, size_t);
#endif

#اگر !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
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
# وگرنه
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  وگرنه
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#endif

#ifndef HAVE_VASPRINTF
صحیح vasprintf(نویسه **, ثابت نویسه *, va_list);
#endif

#ifndef HAVE_VSNPRINTF
صحیح vsnprintf(نویسه *, size_t, ثابت نویسه *, va_list);
#endif

#ifndef HAVE_USER_FROM_UID
نویسه *user_from_uid(uid_t, صحیح);
#endif

#ifndef HAVE_GROUP_FROM_GID
نویسه *group_from_gid(gid_t, صحیح);
#endif

#ifndef HAVE_TIMINGSAFE_BCMP
صحیح timingsafe_bcmp(ثابت تهی *, ثابت تهی *, size_t);
#endif

#ifndef HAVE_BCRYPT_PBKDF
صحیح	bcrypt_pbkdf(ثابت نویسه *, size_t, ثابت uint8_t *, size_t,
    uint8_t *, size_t, unsigned صحیح);
#endif

#ifndef HAVE_EXPLICIT_BZERO
تهی explicit_bzero(تهی *p, size_t n);
#endif

#ifndef HAVE_FREEZERO
تهی freezero(تهی *, size_t);
#endif

#ifndef HAVE_LOCALTIME_R
ساختار tm *localtime_r(ثابت time_t *, ساختار tm *);
#endif

#ifndef HAVE_TIMEGM
#شامل <time.h>
time_t timegm(ساختار tm *);
#endif

نویسه *xcrypt(ثابت نویسه *password, ثابت نویسه *salt);
نویسه *shadow_pw(ساختار passwd *pw);

/* rfc2553 socket API replacements */
#شامل "fake-rfc2553.h"

/* Routines for a single OS platform */
#شامل "bsd-cygwin_util.h"

#شامل "port-aix.h"
#شامل "port-irix.h"
#شامل "port-linux.h"
#شامل "port-solaris.h"
#شامل "port-net.h"
#شامل "port-uw.h"

/* _FORTIFY_SOURCE breaks FD_ISSET(n)/FD_SET(n) for n > FD_SETSIZE. Avoid. */
#اگر defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# اگر defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  اگر __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, set)	kludge_FD_SET(n, set)
#   define FD_ISSET(n, set)	kludge_FD_ISSET(n, set)
تهی kludge_FD_SET(صحیح, fd_set *);
صحیح kludge_FD_ISSET(صحیح, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#endif /* _OPENBSD_COMPAT_H */
