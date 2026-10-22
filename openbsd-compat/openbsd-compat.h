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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <pwd.h>

#அந்தர்பாவ <sys/socket.h>

#அந்தர்பாவ <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#அந்தர்பாவ "base64.h"
#அந்தர்பாவ "sigact.h"
#அந்தர்பாவ "readpassphrase.h"
#அந்தர்பாவ "vis.h"
#அந்தர்பாவ "getrrsetbyname.h"
#அந்தர்பாவ "sha1.h"
#அந்தர்பாவ "bsd-sha2.h"
#அந்தர்பாவ "md5.h"
#அந்தர்பாவ "blf.h"
#அந்தர்பாவ "fnmatch.h"

#ifndef __THROW
# எனில் defined __cplusplus
#  define __THROW throw()
# இல்லையெனில்
#  define __THROW
# endif
#endif

#எனில் defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#endif

#ifndef HAVE_BASENAME
எழுத்து *basename(மாறிலி எழுத்து *path);
#endif

#ifndef HAVE_BINDRESVPORT_SA
முழு bindresvport_sa(முழு sd, கட்டமைப்பு sockaddr *sa);
#endif

#ifndef HAVE_CLOSEFROM
வெறுமை closefrom(முழு);
#endif

#எனில் defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
முழு ftruncate(முழு filedes, off_t length);
#endif

#ifndef HAVE_GETLINE
#அந்தர்பாவ <stdio.h>
ssize_t getline(எழுத்து **, size_t *, FILE *);
#endif

#ifndef HAVE_GETPAGESIZE
முழு getpagesize(வெறுமை);
#endif

#ifndef HAVE_GETCWD
எழுத்து *getcwd(எழுத்து *pt, size_t size);
#endif

#ifndef HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#define getexecpath(a, b) (-1)
#endif

#ifndef HAVE_KILLPG
முழு killpg(pid_t, முழு);
#endif

#எனில் defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
வெறுமை *memmem(மாறிலி வெறுமை *, size_t, மாறிலி வெறுமை *, size_t);
#endif

#ifndef HAVE_REALLOCARRAY
வெறுமை *reallocarray(வெறுமை *, size_t, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
வெறுமை *recallocarray(வெறுமை *, size_t, size_t, size_t);
#endif

#ifndef HAVE_RRESVPORT_AF
முழு rresvport_af(முழு *alport, sa_family_t af);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(எழுத்து *dst, மாறிலி எழுத்து *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(எழுத்து *dst, மாறிலி எழுத்து *src, size_t siz);
#endif

#ifndef HAVE_STRCASESTR
எழுத்து *strcasestr(மாறிலி எழுத்து *, மாறிலி எழுத்து *);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(மாறிலி எழுத்து *, size_t);
#endif

#ifndef HAVE_STRNDUP
எழுத்து *strndup(மாறிலி எழுத்து *s, size_t n);
#endif

#ifndef HAVE_SETENV
முழு setenv(பதிவு மாறிலி எழுத்து *name, பதிவு மாறிலி எழுத்து *மதிப்பு, முழு rewrite);
#endif

#ifndef HAVE_STRMODE
வெறுமை strmode(முழு mode, எழுத்து *p);
#endif

#ifndef HAVE_STRPTIME
#அந்தர்பாவ  <time.h>
எழுத்து *strptime(மாறிலி எழுத்து *buf, மாறிலி எழுத்து *fmt, கட்டமைப்பு tm *tm);
#endif

#எனில் !defined(HAVE_MKDTEMP)
முழு mkstemps(எழுத்து *path, முழு slen);
முழு mkstemp(எழுத்து *path);
எழுத்து *mkdtemp(எழுத்து *path);
#endif

#define mkstemp(x) _ssh_mkstemp(x)
முழு _ssh_mkstemp(எழுத்து *);

#ifndef HAVE_DAEMON
முழு daemon(முழு nochdir, முழு noclose);
#endif

#ifndef HAVE_DIRNAME
எழுத்து *dirname(மாறிலி எழுத்து *path);
#endif

#ifndef HAVE_FMT_SCALED
#define	FMT_SCALED_STRSIZE	7
முழு	fmt_scaled(long long எண், எழுத்து *result);
#endif

#ifndef HAVE_SCAN_SCALED
முழு	scan_scaled(எழுத்து *, long long *);
#endif

#எனில் defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
எழுத்து *inet_ntoa(கட்டமைப்பு in_addr in);
#endif

#ifndef HAVE_INET_NTOP
மாறிலி எழுத்து *inet_ntop(முழு af, மாறிலி வெறுமை *src, எழுத்து *dst, socklen_t size);
#endif

#ifndef HAVE_INET_ATON
முழு inet_aton(மாறிலி எழுத்து *cp, கட்டமைப்பு in_addr *addr);
#endif

#ifndef HAVE_STRSEP
எழுத்து *strsep(எழுத்து **stringp, மாறிலி எழுத்து *delim);
#endif

#ifndef HAVE_SETPROCTITLE
வெறுமை setproctitle(மாறிலி எழுத்து *fmt, ...);
வெறுமை compat_init_setproctitle(முழு argc, எழுத்து *argv[]);
#endif

#ifndef HAVE_GETGROUPLIST
முழு getgrouplist(மாறிலி எழுத்து *, gid_t, gid_t *, முழு *);
#endif

#எனில் !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
முழு BSDgetopt(முழு argc, எழுத்து * மாறிலி *argv, மாறிலி எழுத்து *opts) __THROW;
#அந்தர்பாவ "openbsd-compat/getopt.h"
#endif

#எனில் ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# எனில் defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
முழு readv(முழு, கட்டமைப்பு iovec *, முழு);
# endif

# எனில் defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
முழு writev(முழு, கட்டமைப்பு iovec *, முழு);
# endif
#endif

/* Home grown routines */
#அந்தர்பாவ "bsd-signal.h"
#அந்தர்பாவ "bsd-misc.h"
#அந்தர்பாவ "bsd-setres_id.h"
#அந்தர்பாவ "bsd-statvfs.h"
#அந்தர்பாவ "bsd-waitpid.h"
#அந்தர்பாவ "bsd-poll.h"

#எனில் defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
முழு getpeereid(முழு , uid_t *, gid_t *);
#endif

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(வெறுமை);
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_ARC4RANDOM_BUF
வெறுமை arc4random_buf(வெறுமை *, size_t);
#endif

#ifndef HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#endif

#ifndef HAVE_ASPRINTF
முழு asprintf(எழுத்து **, மாறிலி எழுத்து *, ...);
#endif

#ifndef HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
முழு openpty(முழு *, முழு *, எழுத்து *, மாறிலி கட்டமைப்பு termios *,
    மாறிலி கட்டமைப்பு winsize *);
#endif /* HAVE_OPENPTY */

#ifndef HAVE_SNPRINTF
முழு snprintf(எழுத்து *, size_t, SNPRINTF_CONST எழுத்து *, ...);
#endif

#ifndef HAVE_STRTOLL
long long strtoll(மாறிலி எழுத்து *, எழுத்து **, முழு);
#endif

#ifndef HAVE_STRTOUL
unsigned long strtoul(மாறிலி எழுத்து *, எழுத்து **, முழு);
#endif

#ifndef HAVE_STRTOULL
unsigned long long strtoull(மாறிலி எழுத்து *, எழுத்து **, முழு);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(மாறிலி எழுத்து *, long long, long long, மாறிலி எழுத்து **);
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
முழு mbtowc(wchar_t *, மாறிலி எழுத்து*, size_t);
#endif

#எனில் !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
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
# இல்லையெனில்
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  இல்லையெனில்
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#endif

#ifndef HAVE_VASPRINTF
முழு vasprintf(எழுத்து **, மாறிலி எழுத்து *, va_list);
#endif

#ifndef HAVE_VSNPRINTF
முழு vsnprintf(எழுத்து *, size_t, மாறிலி எழுத்து *, va_list);
#endif

#ifndef HAVE_USER_FROM_UID
எழுத்து *user_from_uid(uid_t, முழு);
#endif

#ifndef HAVE_GROUP_FROM_GID
எழுத்து *group_from_gid(gid_t, முழு);
#endif

#ifndef HAVE_TIMINGSAFE_BCMP
முழு timingsafe_bcmp(மாறிலி வெறுமை *, மாறிலி வெறுமை *, size_t);
#endif

#ifndef HAVE_BCRYPT_PBKDF
முழு	bcrypt_pbkdf(மாறிலி எழுத்து *, size_t, மாறிலி uint8_t *, size_t,
    uint8_t *, size_t, unsigned முழு);
#endif

#ifndef HAVE_EXPLICIT_BZERO
வெறுமை explicit_bzero(வெறுமை *p, size_t n);
#endif

#ifndef HAVE_FREEZERO
வெறுமை freezero(வெறுமை *, size_t);
#endif

#ifndef HAVE_LOCALTIME_R
கட்டமைப்பு tm *localtime_r(மாறிலி time_t *, கட்டமைப்பு tm *);
#endif

#ifndef HAVE_TIMEGM
#அந்தர்பாவ <time.h>
time_t timegm(கட்டமைப்பு tm *);
#endif

எழுத்து *xcrypt(மாறிலி எழுத்து *password, மாறிலி எழுத்து *salt);
எழுத்து *shadow_pw(கட்டமைப்பு passwd *pw);

/* rfc2553 socket API replacements */
#அந்தர்பாவ "fake-rfc2553.h"

/* Routines for a single OS platform */
#அந்தர்பாவ "bsd-cygwin_util.h"

#அந்தர்பாவ "port-aix.h"
#அந்தர்பாவ "port-irix.h"
#அந்தர்பாவ "port-linux.h"
#அந்தர்பாவ "port-solaris.h"
#அந்தர்பாவ "port-net.h"
#அந்தர்பாவ "port-uw.h"

/* _FORTIFY_SOURCE breaks FD_ISSET(n)/FD_SET(n) for n > FD_SETSIZE. Avoid. */
#எனில் defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# எனில் defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  எனில் __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, set)	kludge_FD_SET(n, set)
#   define FD_ISSET(n, set)	kludge_FD_ISSET(n, set)
வெறுமை kludge_FD_SET(முழு, fd_set *);
முழு kludge_FD_ISSET(முழு, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#endif /* _OPENBSD_COMPAT_H */
