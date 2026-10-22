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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <pwd.h>

#অন্তর্ভাব <sys/socket.h>

#অন্তর্ভাব <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#অন্তর্ভাব "base64.h"
#অন্তর্ভাব "sigact.h"
#অন্তর্ভাব "readpassphrase.h"
#অন্তর্ভাব "vis.h"
#অন্তর্ভাব "getrrsetbyname.h"
#অন্তর্ভাব "sha1.h"
#অন্তর্ভাব "bsd-sha2.h"
#অন্তর্ভাব "md5.h"
#অন্তর্ভাব "blf.h"
#অন্তর্ভাব "fnmatch.h"

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
অক্ষর *basename(ধ্রুবক অক্ষর *path);
#endif

#ifndef HAVE_BINDRESVPORT_SA
পূর্ণসংখ্যা bindresvport_sa(পূর্ণসংখ্যা sd, কাঠামো sockaddr *sa);
#endif

#ifndef HAVE_CLOSEFROM
শূন্য closefrom(পূর্ণসংখ্যা);
#endif

#যদি defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
পূর্ণসংখ্যা ftruncate(পূর্ণসংখ্যা filedes, off_t দৈর্ঘ্য);
#endif

#ifndef HAVE_GETLINE
#অন্তর্ভাব <stdio.h>
ssize_t getline(অক্ষর **, আকার_t *, FILE *);
#endif

#ifndef HAVE_GETPAGESIZE
পূর্ণসংখ্যা getpagesize(শূন্য);
#endif

#ifndef HAVE_GETCWD
অক্ষর *getcwd(অক্ষর *pt, আকার_t আকার_2);
#endif

#ifndef HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#define getexecpath(a, b) (-1)
#endif

#ifndef HAVE_KILLPG
পূর্ণসংখ্যা killpg(pid_t, পূর্ণসংখ্যা);
#endif

#যদি defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
শূন্য *memmem(ধ্রুবক শূন্য *, আকার_t, ধ্রুবক শূন্য *, আকার_t);
#endif

#ifndef HAVE_REALLOCARRAY
শূন্য *reallocarray(শূন্য *, আকার_t, আকার_t);
#endif

#ifndef HAVE_RECALLOCARRAY
শূন্য *recallocarray(শূন্য *, আকার_t, আকার_t, আকার_t);
#endif

#ifndef HAVE_RRESVPORT_AF
পূর্ণসংখ্যা rresvport_af(পূর্ণসংখ্যা *alport, sa_family_t af);
#endif

#ifndef HAVE_STRLCPY
আকার_t strlcpy(অক্ষর *dst, ধ্রুবক অক্ষর *src, আকার_t siz);
#endif

#ifndef HAVE_STRLCAT
আকার_t strlcat(অক্ষর *dst, ধ্রুবক অক্ষর *src, আকার_t siz);
#endif

#ifndef HAVE_STRCASESTR
অক্ষর *strcasestr(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
#endif

#ifndef HAVE_STRNLEN
আকার_t strnlen(ধ্রুবক অক্ষর *, আকার_t);
#endif

#ifndef HAVE_STRNDUP
অক্ষর *strndup(ধ্রুবক অক্ষর *s, আকার_t n);
#endif

#ifndef HAVE_SETENV
পূর্ণসংখ্যা setenv(নিবন্ধ ধ্রুবক অক্ষর *name, নিবন্ধ ধ্রুবক অক্ষর *মান, পূর্ণসংখ্যা rewrite);
#endif

#ifndef HAVE_STRMODE
শূন্য strmode(পূর্ণসংখ্যা mode, অক্ষর *p);
#endif

#ifndef HAVE_STRPTIME
#অন্তর্ভাব  <time.h>
অক্ষর *strptime(ধ্রুবক অক্ষর *buf, ধ্রুবক অক্ষর *fmt, কাঠামো tm *tm);
#endif

#যদি !defined(HAVE_MKDTEMP)
পূর্ণসংখ্যা mkstemps(অক্ষর *path, পূর্ণসংখ্যা slen);
পূর্ণসংখ্যা mkstemp(অক্ষর *path);
অক্ষর *mkdtemp(অক্ষর *path);
#endif

#define mkstemp(x) _ssh_mkstemp(x)
পূর্ণসংখ্যা _ssh_mkstemp(অক্ষর *);

#ifndef HAVE_DAEMON
পূর্ণসংখ্যা daemon(পূর্ণসংখ্যা nochdir, পূর্ণসংখ্যা noclose);
#endif

#ifndef HAVE_DIRNAME
অক্ষর *dirname(ধ্রুবক অক্ষর *path);
#endif

#ifndef HAVE_FMT_SCALED
#define	FMT_SCALED_STRSIZE	7
পূর্ণসংখ্যা	fmt_scaled(long long সংখ্যা, অক্ষর *ফলাফল);
#endif

#ifndef HAVE_SCAN_SCALED
পূর্ণসংখ্যা	scan_scaled(অক্ষর *, long long *);
#endif

#যদি defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
অক্ষর *inet_ntoa(কাঠামো in_addr in);
#endif

#ifndef HAVE_INET_NTOP
ধ্রুবক অক্ষর *inet_ntop(পূর্ণসংখ্যা af, ধ্রুবক শূন্য *src, অক্ষর *dst, socklen_t আকার_2);
#endif

#ifndef HAVE_INET_ATON
পূর্ণসংখ্যা inet_aton(ধ্রুবক অক্ষর *cp, কাঠামো in_addr *addr);
#endif

#ifndef HAVE_STRSEP
অক্ষর *strsep(অক্ষর **stringp, ধ্রুবক অক্ষর *delim);
#endif

#ifndef HAVE_SETPROCTITLE
শূন্য setproctitle(ধ্রুবক অক্ষর *fmt, ...);
শূন্য compat_init_setproctitle(পূর্ণসংখ্যা argc, অক্ষর *argv[]);
#endif

#ifndef HAVE_GETGROUPLIST
পূর্ণসংখ্যা getgrouplist(ধ্রুবক অক্ষর *, gid_t, gid_t *, পূর্ণসংখ্যা *);
#endif

#যদি !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
পূর্ণসংখ্যা BSDgetopt(পূর্ণসংখ্যা argc, অক্ষর * ধ্রুবক *argv, ধ্রুবক অক্ষর *opts) __THROW;
#অন্তর্ভাব "openbsd-compat/getopt.h"
#endif

#যদি ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# যদি defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
পূর্ণসংখ্যা readv(পূর্ণসংখ্যা, কাঠামো iovec *, পূর্ণসংখ্যা);
# endif

# যদি defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
পূর্ণসংখ্যা writev(পূর্ণসংখ্যা, কাঠামো iovec *, পূর্ণসংখ্যা);
# endif
#endif

/* Home grown routines */
#অন্তর্ভাব "bsd-signal.h"
#অন্তর্ভাব "bsd-misc.h"
#অন্তর্ভাব "bsd-setres_id.h"
#অন্তর্ভাব "bsd-statvfs.h"
#অন্তর্ভাব "bsd-waitpid.h"
#অন্তর্ভাব "bsd-poll.h"

#যদি defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
পূর্ণসংখ্যা getpeereid(পূর্ণসংখ্যা , uid_t *, gid_t *);
#endif

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(শূন্য);
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_ARC4RANDOM_BUF
শূন্য arc4random_buf(শূন্য *, আকার_t);
#endif

#ifndef HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#endif

#ifndef HAVE_ASPRINTF
পূর্ণসংখ্যা asprintf(অক্ষর **, ধ্রুবক অক্ষর *, ...);
#endif

#ifndef HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
পূর্ণসংখ্যা openpty(পূর্ণসংখ্যা *, পূর্ণসংখ্যা *, অক্ষর *, ধ্রুবক কাঠামো termios *,
    ধ্রুবক কাঠামো winsize *);
#endif /* HAVE_OPENPTY */

#ifndef HAVE_SNPRINTF
পূর্ণসংখ্যা snprintf(অক্ষর *, আকার_t, SNPRINTF_CONST অক্ষর *, ...);
#endif

#ifndef HAVE_STRTOLL
long long strtoll(ধ্রুবক অক্ষর *, অক্ষর **, পূর্ণসংখ্যা);
#endif

#ifndef HAVE_STRTOUL
unsigned long strtoul(ধ্রুবক অক্ষর *, অক্ষর **, পূর্ণসংখ্যা);
#endif

#ifndef HAVE_STRTOULL
unsigned long long strtoull(ধ্রুবক অক্ষর *, অক্ষর **, পূর্ণসংখ্যা);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(ধ্রুবক অক্ষর *, long long, long long, ধ্রুবক অক্ষর **);
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
পূর্ণসংখ্যা mbtowc(wchar_t *, ধ্রুবক অক্ষর*, আকার_t);
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
পূর্ণসংখ্যা vasprintf(অক্ষর **, ধ্রুবক অক্ষর *, va_list);
#endif

#ifndef HAVE_VSNPRINTF
পূর্ণসংখ্যা vsnprintf(অক্ষর *, আকার_t, ধ্রুবক অক্ষর *, va_list);
#endif

#ifndef HAVE_USER_FROM_UID
অক্ষর *user_from_uid(uid_t, পূর্ণসংখ্যা);
#endif

#ifndef HAVE_GROUP_FROM_GID
অক্ষর *group_from_gid(gid_t, পূর্ণসংখ্যা);
#endif

#ifndef HAVE_TIMINGSAFE_BCMP
পূর্ণসংখ্যা timingsafe_bcmp(ধ্রুবক শূন্য *, ধ্রুবক শূন্য *, আকার_t);
#endif

#ifndef HAVE_BCRYPT_PBKDF
পূর্ণসংখ্যা	bcrypt_pbkdf(ধ্রুবক অক্ষর *, আকার_t, ধ্রুবক uint8_t *, আকার_t,
    uint8_t *, আকার_t, unsigned পূর্ণসংখ্যা);
#endif

#ifndef HAVE_EXPLICIT_BZERO
শূন্য explicit_bzero(শূন্য *p, আকার_t n);
#endif

#ifndef HAVE_FREEZERO
শূন্য freezero(শূন্য *, আকার_t);
#endif

#ifndef HAVE_LOCALTIME_R
কাঠামো tm *localtime_r(ধ্রুবক time_t *, কাঠামো tm *);
#endif

#ifndef HAVE_TIMEGM
#অন্তর্ভাব <time.h>
time_t timegm(কাঠামো tm *);
#endif

অক্ষর *xcrypt(ধ্রুবক অক্ষর *password, ধ্রুবক অক্ষর *salt);
অক্ষর *shadow_pw(কাঠামো passwd *pw);

/* rfc2553 socket API replacements */
#অন্তর্ভাব "fake-rfc2553.h"

/* Routines for a single OS platform */
#অন্তর্ভাব "bsd-cygwin_util.h"

#অন্তর্ভাব "port-aix.h"
#অন্তর্ভাব "port-irix.h"
#অন্তর্ভাব "port-linux.h"
#অন্তর্ভাব "port-solaris.h"
#অন্তর্ভাব "port-net.h"
#অন্তর্ভাব "port-uw.h"

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
শূন্য kludge_FD_SET(পূর্ণসংখ্যা, fd_set *);
পূর্ণসংখ্যা kludge_FD_ISSET(পূর্ণসংখ্যা, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#endif /* _OPENBSD_COMPAT_H */
