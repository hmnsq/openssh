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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <pwd.h>

#অন্তর্ভাৱ <sys/socket.h>

#অন্তর্ভাৱ <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#অন্তর্ভাৱ "base64.h"
#অন্তর্ভাৱ "sigact.h"
#অন্তর্ভাৱ "readpassphrase.h"
#অন্তর্ভাৱ "vis.h"
#অন্তর্ভাৱ "getrrsetbyname.h"
#অন্তর্ভাৱ "sha1.h"
#অন্তর্ভাৱ "bsd-sha2.h"
#অন্তর্ভাৱ "md5.h"
#অন্তর্ভাৱ "blf.h"
#অন্তর্ভাৱ "fnmatch.h"

#ifndef __THROW
# যদি defined __cplusplus
#  define __THROW throw()
# অন্যথা
#  define __THROW
# endif
#endif

#যদি defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#endif

#ifndef HAVE_BASENAME
ৱর্ণ *basename(ধ্রুৱ ৱর্ণ *path);
#endif

#ifndef HAVE_BINDRESVPORT_SA
পূর্ণাঙ্ক bindresvport_sa(পূর্ণাঙ্ক sd, সংরচনা sockaddr *sa);
#endif

#ifndef HAVE_CLOSEFROM
শূন্য closefrom(পূর্ণাঙ্ক);
#endif

#যদি defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
পূর্ণাঙ্ক ftruncate(পূর্ণাঙ্ক filedes, off_t length);
#endif

#ifndef HAVE_GETLINE
#অন্তর্ভাৱ <stdio.h>
ssize_t getline(ৱর্ণ **, size_t *, FILE *);
#endif

#ifndef HAVE_GETPAGESIZE
পূর্ণাঙ্ক getpagesize(শূন্য);
#endif

#ifndef HAVE_GETCWD
ৱর্ণ *getcwd(ৱর্ণ *pt, size_t size);
#endif

#ifndef HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#define getexecpath(a, b) (-1)
#endif

#ifndef HAVE_KILLPG
পূর্ণাঙ্ক killpg(pid_t, পূর্ণাঙ্ক);
#endif

#যদি defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
শূন্য *memmem(ধ্রুৱ শূন্য *, size_t, ধ্রুৱ শূন্য *, size_t);
#endif

#ifndef HAVE_REALLOCARRAY
শূন্য *reallocarray(শূন্য *, size_t, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
শূন্য *recallocarray(শূন্য *, size_t, size_t, size_t);
#endif

#ifndef HAVE_RRESVPORT_AF
পূর্ণাঙ্ক rresvport_af(পূর্ণাঙ্ক *alport, sa_family_t af);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(ৱর্ণ *dst, ধ্রুৱ ৱর্ণ *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(ৱর্ণ *dst, ধ্রুৱ ৱর্ণ *src, size_t siz);
#endif

#ifndef HAVE_STRCASESTR
ৱর্ণ *strcasestr(ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(ধ্রুৱ ৱর্ণ *, size_t);
#endif

#ifndef HAVE_STRNDUP
ৱর্ণ *strndup(ধ্রুৱ ৱর্ণ *s, size_t n);
#endif

#ifndef HAVE_SETENV
পূর্ণাঙ্ক setenv(পঞ্জিকা ধ্রুৱ ৱর্ণ *name, পঞ্জিকা ধ্রুৱ ৱর্ণ *মান, পূর্ণাঙ্ক rewrite);
#endif

#ifndef HAVE_STRMODE
শূন্য strmode(পূর্ণাঙ্ক mode, ৱর্ণ *p);
#endif

#ifndef HAVE_STRPTIME
#অন্তর্ভাৱ  <time.h>
ৱর্ণ *strptime(ধ্রুৱ ৱর্ণ *buf, ধ্রুৱ ৱর্ণ *fmt, সংরচনা tm *tm);
#endif

#যদি !defined(HAVE_MKDTEMP)
পূর্ণাঙ্ক mkstemps(ৱর্ণ *path, পূর্ণাঙ্ক slen);
পূর্ণাঙ্ক mkstemp(ৱর্ণ *path);
ৱর্ণ *mkdtemp(ৱর্ণ *path);
#endif

#define mkstemp(x) _ssh_mkstemp(x)
পূর্ণাঙ্ক _ssh_mkstemp(ৱর্ণ *);

#ifndef HAVE_DAEMON
পূর্ণাঙ্ক daemon(পূর্ণাঙ্ক nochdir, পূর্ণাঙ্ক noclose);
#endif

#ifndef HAVE_DIRNAME
ৱর্ণ *dirname(ধ্রুৱ ৱর্ণ *path);
#endif

#ifndef HAVE_FMT_SCALED
#define	FMT_SCALED_STRSIZE	7
পূর্ণাঙ্ক	fmt_scaled(long long সংখ্যা, ৱর্ণ *result);
#endif

#ifndef HAVE_SCAN_SCALED
পূর্ণাঙ্ক	scan_scaled(ৱর্ণ *, long long *);
#endif

#যদি defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
ৱর্ণ *inet_ntoa(সংরচনা in_addr in);
#endif

#ifndef HAVE_INET_NTOP
ধ্রুৱ ৱর্ণ *inet_ntop(পূর্ণাঙ্ক af, ধ্রুৱ শূন্য *src, ৱর্ণ *dst, socklen_t size);
#endif

#ifndef HAVE_INET_ATON
পূর্ণাঙ্ক inet_aton(ধ্রুৱ ৱর্ণ *cp, সংরচনা in_addr *addr);
#endif

#ifndef HAVE_STRSEP
ৱর্ণ *strsep(ৱর্ণ **stringp, ধ্রুৱ ৱর্ণ *delim);
#endif

#ifndef HAVE_SETPROCTITLE
শূন্য setproctitle(ধ্রুৱ ৱর্ণ *fmt, ...);
শূন্য compat_init_setproctitle(পূর্ণাঙ্ক argc, ৱর্ণ *argv[]);
#endif

#ifndef HAVE_GETGROUPLIST
পূর্ণাঙ্ক getgrouplist(ধ্রুৱ ৱর্ণ *, gid_t, gid_t *, পূর্ণাঙ্ক *);
#endif

#যদি !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
পূর্ণাঙ্ক BSDgetopt(পূর্ণাঙ্ক argc, ৱর্ণ * ধ্রুৱ *argv, ধ্রুৱ ৱর্ণ *opts) __THROW;
#অন্তর্ভাৱ "openbsd-compat/getopt.h"
#endif

#যদি ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# যদি defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
পূর্ণাঙ্ক readv(পূর্ণাঙ্ক, সংরচনা iovec *, পূর্ণাঙ্ক);
# endif

# যদি defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
পূর্ণাঙ্ক writev(পূর্ণাঙ্ক, সংরচনা iovec *, পূর্ণাঙ্ক);
# endif
#endif

/* Home grown routines */
#অন্তর্ভাৱ "bsd-signal.h"
#অন্তর্ভাৱ "bsd-misc.h"
#অন্তর্ভাৱ "bsd-setres_id.h"
#অন্তর্ভাৱ "bsd-statvfs.h"
#অন্তর্ভাৱ "bsd-waitpid.h"
#অন্তর্ভাৱ "bsd-poll.h"

#যদি defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
পূর্ণাঙ্ক getpeereid(পূর্ণাঙ্ক , uid_t *, gid_t *);
#endif

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(শূন্য);
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_ARC4RANDOM_BUF
শূন্য arc4random_buf(শূন্য *, size_t);
#endif

#ifndef HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#endif

#ifndef HAVE_ASPRINTF
পূর্ণাঙ্ক asprintf(ৱর্ণ **, ধ্রুৱ ৱর্ণ *, ...);
#endif

#ifndef HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
পূর্ণাঙ্ক openpty(পূর্ণাঙ্ক *, পূর্ণাঙ্ক *, ৱর্ণ *, ধ্রুৱ সংরচনা termios *,
    ধ্রুৱ সংরচনা winsize *);
#endif /* HAVE_OPENPTY */

#ifndef HAVE_SNPRINTF
পূর্ণাঙ্ক snprintf(ৱর্ণ *, size_t, SNPRINTF_CONST ৱর্ণ *, ...);
#endif

#ifndef HAVE_STRTOLL
long long strtoll(ধ্রুৱ ৱর্ণ *, ৱর্ণ **, পূর্ণাঙ্ক);
#endif

#ifndef HAVE_STRTOUL
unsigned long strtoul(ধ্রুৱ ৱর্ণ *, ৱর্ণ **, পূর্ণাঙ্ক);
#endif

#ifndef HAVE_STRTOULL
unsigned long long strtoull(ধ্রুৱ ৱর্ণ *, ৱর্ণ **, পূর্ণাঙ্ক);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(ধ্রুৱ ৱর্ণ *, long long, long long, ধ্রুৱ ৱর্ণ **);
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
পূর্ণাঙ্ক mbtowc(wchar_t *, ধ্রুৱ ৱর্ণ*, size_t);
#endif

#যদি !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
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
# অন্যথা
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  অন্যথা
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#endif

#ifndef HAVE_VASPRINTF
পূর্ণাঙ্ক vasprintf(ৱর্ণ **, ধ্রুৱ ৱর্ণ *, va_list);
#endif

#ifndef HAVE_VSNPRINTF
পূর্ণাঙ্ক vsnprintf(ৱর্ণ *, size_t, ধ্রুৱ ৱর্ণ *, va_list);
#endif

#ifndef HAVE_USER_FROM_UID
ৱর্ণ *user_from_uid(uid_t, পূর্ণাঙ্ক);
#endif

#ifndef HAVE_GROUP_FROM_GID
ৱর্ণ *group_from_gid(gid_t, পূর্ণাঙ্ক);
#endif

#ifndef HAVE_TIMINGSAFE_BCMP
পূর্ণাঙ্ক timingsafe_bcmp(ধ্রুৱ শূন্য *, ধ্রুৱ শূন্য *, size_t);
#endif

#ifndef HAVE_BCRYPT_PBKDF
পূর্ণাঙ্ক	bcrypt_pbkdf(ধ্রুৱ ৱর্ণ *, size_t, ধ্রুৱ uint8_t *, size_t,
    uint8_t *, size_t, unsigned পূর্ণাঙ্ক);
#endif

#ifndef HAVE_EXPLICIT_BZERO
শূন্য explicit_bzero(শূন্য *p, size_t n);
#endif

#ifndef HAVE_FREEZERO
শূন্য freezero(শূন্য *, size_t);
#endif

#ifndef HAVE_LOCALTIME_R
সংরচনা tm *localtime_r(ধ্রুৱ time_t *, সংরচনা tm *);
#endif

#ifndef HAVE_TIMEGM
#অন্তর্ভাৱ <time.h>
time_t timegm(সংরচনা tm *);
#endif

ৱর্ণ *xcrypt(ধ্রুৱ ৱর্ণ *password, ধ্রুৱ ৱর্ণ *salt);
ৱর্ণ *shadow_pw(সংরচনা passwd *pw);

/* rfc2553 socket API replacements */
#অন্তর্ভাৱ "fake-rfc2553.h"

/* Routines for a single OS platform */
#অন্তর্ভাৱ "bsd-cygwin_util.h"

#অন্তর্ভাৱ "port-aix.h"
#অন্তর্ভাৱ "port-irix.h"
#অন্তর্ভাৱ "port-linux.h"
#অন্তর্ভাৱ "port-solaris.h"
#অন্তর্ভাৱ "port-net.h"
#অন্তর্ভাৱ "port-uw.h"

/* _FORTIFY_SOURCE breaks FD_ISSET(n)/FD_SET(n) for n > FD_SETSIZE. Avoid. */
#যদি defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# যদি defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  যদি __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, set)	kludge_FD_SET(n, set)
#   define FD_ISSET(n, set)	kludge_FD_ISSET(n, set)
শূন্য kludge_FD_SET(পূর্ণাঙ্ক, fd_set *);
পূর্ণাঙ্ক kludge_FD_ISSET(পূর্ণাঙ্ক, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#endif /* _OPENBSD_COMPAT_H */
