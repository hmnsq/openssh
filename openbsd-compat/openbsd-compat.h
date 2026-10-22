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
# если defined __cplusplus
#  define __THROW throw()
# иначе
#  define __THROW
# endif
#endif

#если defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#endif

#ifndef HAVE_BASENAME
char *basename(const char *path);
#endif

#ifndef HAVE_BINDRESVPORT_SA
целое bindresvport_sa(целое sd, struct sockaddr *sa);
#endif

#ifndef HAVE_CLOSEFROM
void closefrom(целое);
#endif

#если defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
целое ftruncate(целое filedes, off_t length);
#endif

#ifndef HAVE_GETLINE
#include <stdio.h>
ssize_t getline(char **, size_t *, FILE *);
#endif

#ifndef HAVE_GETPAGESIZE
целое getpagesize(void);
#endif

#ifndef HAVE_GETCWD
char *getcwd(char *pt, size_t size);
#endif

#ifndef HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#define getexecpath(a, b) (-1)
#endif

#ifndef HAVE_KILLPG
целое killpg(pid_t, целое);
#endif

#если defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
void *memmem(const void *, size_t, const void *, size_t);
#endif

#ifndef HAVE_REALLOCARRAY
void *reallocarray(void *, size_t, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
void *recallocarray(void *, size_t, size_t, size_t);
#endif

#ifndef HAVE_RRESVPORT_AF
целое rresvport_af(целое *alport, sa_family_t af);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_STRCASESTR
char *strcasestr(const char *, const char *);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(const char *, size_t);
#endif

#ifndef HAVE_STRNDUP
char *strndup(const char *s, size_t n);
#endif

#ifndef HAVE_SETENV
целое setenv(register const char *name, register const char *value, целое rewrite);
#endif

#ifndef HAVE_STRMODE
void strmode(целое mode, char *p);
#endif

#ifndef HAVE_STRPTIME
#include  <time.h>
char *strptime(const char *buf, const char *fmt, struct tm *tm);
#endif

#если !defined(HAVE_MKDTEMP)
целое mkstemps(char *path, целое slen);
целое mkstemp(char *path);
char *mkdtemp(char *path);
#endif

#define mkstemp(x) _ssh_mkstemp(x)
целое _ssh_mkstemp(char *);

#ifndef HAVE_DAEMON
целое daemon(целое nochdir, целое noclose);
#endif

#ifndef HAVE_DIRNAME
char *dirname(const char *path);
#endif

#ifndef HAVE_FMT_SCALED
#define	FMT_SCALED_STRSIZE	7
целое	fmt_scaled(long long number, char *result);
#endif

#ifndef HAVE_SCAN_SCALED
целое	scan_scaled(char *, long long *);
#endif

#если defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
char *inet_ntoa(struct in_addr in);
#endif

#ifndef HAVE_INET_NTOP
const char *inet_ntop(целое af, const void *src, char *dst, socklen_t size);
#endif

#ifndef HAVE_INET_ATON
целое inet_aton(const char *cp, struct in_addr *addr);
#endif

#ifndef HAVE_STRSEP
char *strsep(char **stringp, const char *delim);
#endif

#ifndef HAVE_SETPROCTITLE
void setproctitle(const char *fmt, ...);
void compat_init_setproctitle(целое argc, char *argv[]);
#endif

#ifndef HAVE_GETGROUPLIST
целое getgrouplist(const char *, gid_t, gid_t *, целое *);
#endif

#если !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
целое BSDgetopt(целое argc, char * const *argv, const char *opts) __THROW;
#include "openbsd-compat/getopt.h"
#endif

#если ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# если defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
целое readv(целое, struct iovec *, целое);
# endif

# если defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
целое writev(целое, struct iovec *, целое);
# endif
#endif

/* Home grown routines */
#include "bsd-signal.h"
#include "bsd-misc.h"
#include "bsd-setres_id.h"
#include "bsd-statvfs.h"
#include "bsd-waitpid.h"
#include "bsd-poll.h"

#если defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
целое getpeereid(целое , uid_t *, gid_t *);
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
целое asprintf(char **, const char *, ...);
#endif

#ifndef HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
целое openpty(целое *, целое *, char *, const struct termios *,
    const struct winsize *);
#endif /* HAVE_OPENPTY */

#ifndef HAVE_SNPRINTF
целое snprintf(char *, size_t, SNPRINTF_CONST char *, ...);
#endif

#ifndef HAVE_STRTOLL
long long strtoll(const char *, char **, целое);
#endif

#ifndef HAVE_STRTOUL
unsigned long strtoul(const char *, char **, целое);
#endif

#ifndef HAVE_STRTOULL
unsigned long long strtoull(const char *, char **, целое);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(const char *, long long, long long, const char **);
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
целое mbtowc(wchar_t *, const char*, size_t);
#endif

#если !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
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
# иначе
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  иначе
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#endif

#ifndef HAVE_VASPRINTF
целое vasprintf(char **, const char *, va_list);
#endif

#ifndef HAVE_VSNPRINTF
целое vsnprintf(char *, size_t, const char *, va_list);
#endif

#ifndef HAVE_USER_FROM_UID
char *user_from_uid(uid_t, целое);
#endif

#ifndef HAVE_GROUP_FROM_GID
char *group_from_gid(gid_t, целое);
#endif

#ifndef HAVE_TIMINGSAFE_BCMP
целое timingsafe_bcmp(const void *, const void *, size_t);
#endif

#ifndef HAVE_BCRYPT_PBKDF
целое	bcrypt_pbkdf(const char *, size_t, const uint8_t *, size_t,
    uint8_t *, size_t, unsigned целое);
#endif

#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void *p, size_t n);
#endif

#ifndef HAVE_FREEZERO
void freezero(void *, size_t);
#endif

#ifndef HAVE_LOCALTIME_R
struct tm *localtime_r(const time_t *, struct tm *);
#endif

#ifndef HAVE_TIMEGM
#include <time.h>
time_t timegm(struct tm *);
#endif

char *xcrypt(const char *password, const char *salt);
char *shadow_pw(struct passwd *pw);

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
#если defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# если defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  если __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, set)	kludge_FD_SET(n, set)
#   define FD_ISSET(n, set)	kludge_FD_ISSET(n, set)
void kludge_FD_SET(целое, fd_set *);
целое kludge_FD_ISSET(целое, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#endif /* _OPENBSD_COMPAT_H */
