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

#include "includes.h"

#include <sys/types.h>
#include <pwd.h>

#include <sys/socket.h>

#include <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#include "base64.h"
#include "sigact.h"
#include "readpassphrase.h"
#include "vis.h"
#include "getrrsetbyname.h"
#include "sha1.h"
#include "bsd-sha2.h"
#include "md5.h"
#include "blf.h"
#include "fnmatch.h"

#ifndef __THROW
# གལ་ཏེ defined __cplusplus
#  define __THROW throw()
# དེ་མིན
#  define __THROW
# endif
#endif

#གལ་ཏེ defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#endif

#ifndef HAVE_BASENAME
var_na *basename(const var_na *path);
#endif

#ifndef HAVE_BINDRESVPORT_SA
ཧྲིལ bindresvport_sa(ཧྲིལ sd, sa_nracanaa sockaddr *sa);
#endif

#ifndef HAVE_CLOSEFROM
void closefrom(ཧྲིལ);
#endif

#གལ་ཏེ defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
ཧྲིལ ftruncate(ཧྲིལ filedes, off_t length);
#endif

#ifndef HAVE_GETLINE
#include <stdio.h>
ssize_t getline(var_na **, size_t *, FILE *);
#endif

#ifndef HAVE_GETPAGESIZE
ཧྲིལ getpagesize(void);
#endif

#ifndef HAVE_GETCWD
var_na *getcwd(var_na *pt, size_t size);
#endif

#ifndef HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#define getexecpath(a, b) (-1)
#endif

#ifndef HAVE_KILLPG
ཧྲིལ killpg(pid_t, ཧྲིལ);
#endif

#གལ་ཏེ defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
void *memmem(const void *, size_t, const void *, size_t);
#endif

#ifndef HAVE_REALLOCARRAY
void *reallocarray(void *, size_t, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
void *recallocarray(void *, size_t, size_t, size_t);
#endif

#ifndef HAVE_RRESVPORT_AF
ཧྲིལ rresvport_af(ཧྲིལ *alport, sa_family_t af);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(var_na *dst, const var_na *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(var_na *dst, const var_na *src, size_t siz);
#endif

#ifndef HAVE_STRCASESTR
var_na *strcasestr(const var_na *, const var_na *);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(const var_na *, size_t);
#endif

#ifndef HAVE_STRNDUP
var_na *strndup(const var_na *s, size_t n);
#endif

#ifndef HAVE_SETENV
ཧྲིལ setenv(pa_njikaa const var_na *name, pa_njikaa const var_na *value, ཧྲིལ rewrite);
#endif

#ifndef HAVE_STRMODE
void strmode(ཧྲིལ mode, var_na *p);
#endif

#ifndef HAVE_STRPTIME
#include  <time.h>
var_na *strptime(const var_na *buf, const var_na *fmt, sa_nracanaa tm *tm);
#endif

#གལ་ཏེ !defined(HAVE_MKDTEMP)
ཧྲིལ mkstemps(var_na *path, ཧྲིལ slen);
ཧྲིལ mkstemp(var_na *path);
var_na *mkdtemp(var_na *path);
#endif

#define mkstemp(x) _ssh_mkstemp(x)
ཧྲིལ _ssh_mkstemp(var_na *);

#ifndef HAVE_DAEMON
ཧྲིལ daemon(ཧྲིལ nochdir, ཧྲིལ noclose);
#endif

#ifndef HAVE_DIRNAME
var_na *dirname(const var_na *path);
#endif

#ifndef HAVE_FMT_SCALED
#define	FMT_SCALED_STRSIZE	7
ཧྲིལ	fmt_scaled(long long number, var_na *result);
#endif

#ifndef HAVE_SCAN_SCALED
ཧྲིལ	scan_scaled(var_na *, long long *);
#endif

#གལ་ཏེ defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
var_na *inet_ntoa(sa_nracanaa in_addr in);
#endif

#ifndef HAVE_INET_NTOP
const var_na *inet_ntop(ཧྲིལ af, const void *src, var_na *dst, socklen_t size);
#endif

#ifndef HAVE_INET_ATON
ཧྲིལ inet_aton(const var_na *cp, sa_nracanaa in_addr *addr);
#endif

#ifndef HAVE_STRSEP
var_na *strsep(var_na **stringp, const var_na *delim);
#endif

#ifndef HAVE_SETPROCTITLE
void setproctitle(const var_na *fmt, ...);
void compat_init_setproctitle(ཧྲིལ argc, var_na *argv[]);
#endif

#ifndef HAVE_GETGROUPLIST
ཧྲིལ getgrouplist(const var_na *, gid_t, gid_t *, ཧྲིལ *);
#endif

#གལ་ཏེ !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
ཧྲིལ BSDgetopt(ཧྲིལ argc, var_na * const *argv, const var_na *opts) __THROW;
#include "openbsd-compat/getopt.h"
#endif

#གལ་ཏེ ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# གལ་ཏེ defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
ཧྲིལ readv(ཧྲིལ, sa_nracanaa iovec *, ཧྲིལ);
# endif

# གལ་ཏེ defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
ཧྲིལ writev(ཧྲིལ, sa_nracanaa iovec *, ཧྲིལ);
# endif
#endif

/* Home grown routines */
#include "bsd-signal.h"
#include "bsd-misc.h"
#include "bsd-setres_id.h"
#include "bsd-statvfs.h"
#include "bsd-waitpid.h"
#include "bsd-poll.h"

#གལ་ཏེ defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
ཧྲིལ getpeereid(ཧྲིལ , uid_t *, gid_t *);
#endif

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(void);
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_ARC4RANDOM_BUF
void arc4random_buf(void *, size_t);
#endif

#ifndef HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#endif

#ifndef HAVE_ASPRINTF
ཧྲིལ asprintf(var_na **, const var_na *, ...);
#endif

#ifndef HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
ཧྲིལ openpty(ཧྲིལ *, ཧྲིལ *, var_na *, const sa_nracanaa termios *,
    const sa_nracanaa winsize *);
#endif /* HAVE_OPENPTY */

#ifndef HAVE_SNPRINTF
ཧྲིལ snprintf(var_na *, size_t, SNPRINTF_CONST var_na *, ...);
#endif

#ifndef HAVE_STRTOLL
long long strtoll(const var_na *, var_na **, ཧྲིལ);
#endif

#ifndef HAVE_STRTOUL
unsigned long strtoul(const var_na *, var_na **, ཧྲིལ);
#endif

#ifndef HAVE_STRTOULL
unsigned long long strtoull(const var_na *, var_na **, ཧྲིལ);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(const var_na *, long long, long long, const var_na **);
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
ཧྲིལ mbtowc(wchar_t *, const var_na*, size_t);
#endif

#གལ་ཏེ !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
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
# དེ་མིན
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  དེ་མིན
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#endif

#ifndef HAVE_VASPRINTF
ཧྲིལ vasprintf(var_na **, const var_na *, va_list);
#endif

#ifndef HAVE_VSNPRINTF
ཧྲིལ vsnprintf(var_na *, size_t, const var_na *, va_list);
#endif

#ifndef HAVE_USER_FROM_UID
var_na *user_from_uid(uid_t, ཧྲིལ);
#endif

#ifndef HAVE_GROUP_FROM_GID
var_na *group_from_gid(gid_t, ཧྲིལ);
#endif

#ifndef HAVE_TIMINGSAFE_BCMP
ཧྲིལ timingsafe_bcmp(const void *, const void *, size_t);
#endif

#ifndef HAVE_BCRYPT_PBKDF
ཧྲིལ	bcrypt_pbkdf(const var_na *, size_t, const uint8_t *, size_t,
    uint8_t *, size_t, unsigned ཧྲིལ);
#endif

#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void *p, size_t n);
#endif

#ifndef HAVE_FREEZERO
void freezero(void *, size_t);
#endif

#ifndef HAVE_LOCALTIME_R
sa_nracanaa tm *localtime_r(const time_t *, sa_nracanaa tm *);
#endif

#ifndef HAVE_TIMEGM
#include <time.h>
time_t timegm(sa_nracanaa tm *);
#endif

var_na *xcrypt(const var_na *password, const var_na *salt);
var_na *shadow_pw(sa_nracanaa passwd *pw);

/* rfc2553 socket API replacements */
#include "fake-rfc2553.h"

/* Routines for a single OS platform */
#include "bsd-cygwin_util.h"

#include "port-aix.h"
#include "port-irix.h"
#include "port-linux.h"
#include "port-solaris.h"
#include "port-net.h"
#include "port-uw.h"

/* _FORTIFY_SOURCE breaks FD_ISSET(n)/FD_SET(n) for n > FD_SETSIZE. Avoid. */
#གལ་ཏེ defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# གལ་ཏེ defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  གལ་ཏེ __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, set)	kludge_FD_SET(n, set)
#   define FD_ISSET(n, set)	kludge_FD_ISSET(n, set)
void kludge_FD_SET(ཧྲིལ, fd_set *);
ཧྲིལ kludge_FD_ISSET(ཧྲིལ, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#endif /* _OPENBSD_COMPAT_H */
