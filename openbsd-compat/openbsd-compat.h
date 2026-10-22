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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>

#ଅନ୍ତର୍ଭାଵ <sys/socket.h>

#ଅନ୍ତର୍ଭାଵ <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#ଅନ୍ତର୍ଭାଵ "base64.h"
#ଅନ୍ତର୍ଭାଵ "sigact.h"
#ଅନ୍ତର୍ଭାଵ "readpassphrase.h"
#ଅନ୍ତର୍ଭାଵ "vis.h"
#ଅନ୍ତର୍ଭାଵ "getrrsetbyname.h"
#ଅନ୍ତର୍ଭାଵ "sha1.h"
#ଅନ୍ତର୍ଭାଵ "bsd-sha2.h"
#ଅନ୍ତର୍ଭାଵ "md5.h"
#ଅନ୍ତର୍ଭାଵ "blf.h"
#ଅନ୍ତର୍ଭାଵ "fnmatch.h"

#ifndef __THROW
# ଯଦି defined __cplusplus
#  define __THROW throw()
# ଅନ୍ୟଥା
#  define __THROW
# endif
#endif

#ଯଦି defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#endif

#ifndef HAVE_BASENAME
ଅକ୍ଷର *basename(ଅଚଳ ଅକ୍ଷର *path);
#endif

#ifndef HAVE_BINDRESVPORT_SA
ପୂର୍ଣ୍ଣସଂଖ୍ୟା bindresvport_sa(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sd, ସଂରଚନା sockaddr *sa);
#endif

#ifndef HAVE_CLOSEFROM
ଶୂନ୍ୟ closefrom(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#endif

#ଯଦି defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ftruncate(ପୂର୍ଣ୍ଣସଂଖ୍ୟା filedes, off_t length);
#endif

#ifndef HAVE_GETLINE
#ଅନ୍ତର୍ଭାଵ <stdio.h>
ssize_t getline(ଅକ୍ଷର **, size_t *, FILE *);
#endif

#ifndef HAVE_GETPAGESIZE
ପୂର୍ଣ୍ଣସଂଖ୍ୟା getpagesize(ଶୂନ୍ୟ);
#endif

#ifndef HAVE_GETCWD
ଅକ୍ଷର *getcwd(ଅକ୍ଷର *pt, size_t size);
#endif

#ifndef HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#define getexecpath(a, b) (-1)
#endif

#ifndef HAVE_KILLPG
ପୂର୍ଣ୍ଣସଂଖ୍ୟା killpg(pid_t, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#endif

#ଯଦି defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
ଶୂନ୍ୟ *memmem(ଅଚଳ ଶୂନ୍ୟ *, size_t, ଅଚଳ ଶୂନ୍ୟ *, size_t);
#endif

#ifndef HAVE_REALLOCARRAY
ଶୂନ୍ୟ *reallocarray(ଶୂନ୍ୟ *, size_t, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
ଶୂନ୍ୟ *recallocarray(ଶୂନ୍ୟ *, size_t, size_t, size_t);
#endif

#ifndef HAVE_RRESVPORT_AF
ପୂର୍ଣ୍ଣସଂଖ୍ୟା rresvport_af(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *alport, sa_family_t af);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(ଅକ୍ଷର *dst, ଅଚଳ ଅକ୍ଷର *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(ଅକ୍ଷର *dst, ଅଚଳ ଅକ୍ଷର *src, size_t siz);
#endif

#ifndef HAVE_STRCASESTR
ଅକ୍ଷର *strcasestr(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(ଅଚଳ ଅକ୍ଷର *, size_t);
#endif

#ifndef HAVE_STRNDUP
ଅକ୍ଷର *strndup(ଅଚଳ ଅକ୍ଷର *s, size_t n);
#endif

#ifndef HAVE_SETENV
ପୂର୍ଣ୍ଣସଂଖ୍ୟା setenv(ପଞ୍ଜିକରଣ ଅଚଳ ଅକ୍ଷର *name, ପଞ୍ଜିକରଣ ଅଚଳ ଅକ୍ଷର *ମୂଲ୍ୟ, ପୂର୍ଣ୍ଣସଂଖ୍ୟା rewrite);
#endif

#ifndef HAVE_STRMODE
ଶୂନ୍ୟ strmode(ପୂର୍ଣ୍ଣସଂଖ୍ୟା mode, ଅକ୍ଷର *p);
#endif

#ifndef HAVE_STRPTIME
#ଅନ୍ତର୍ଭାଵ  <time.h>
ଅକ୍ଷର *strptime(ଅଚଳ ଅକ୍ଷର *buf, ଅଚଳ ଅକ୍ଷର *fmt, ସଂରଚନା tm *tm);
#endif

#ଯଦି !defined(HAVE_MKDTEMP)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mkstemps(ଅକ୍ଷର *path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା slen);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mkstemp(ଅକ୍ଷର *path);
ଅକ୍ଷର *mkdtemp(ଅକ୍ଷର *path);
#endif

#define mkstemp(x) _ssh_mkstemp(x)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା _ssh_mkstemp(ଅକ୍ଷର *);

#ifndef HAVE_DAEMON
ପୂର୍ଣ୍ଣସଂଖ୍ୟା daemon(ପୂର୍ଣ୍ଣସଂଖ୍ୟା nochdir, ପୂର୍ଣ୍ଣସଂଖ୍ୟା noclose);
#endif

#ifndef HAVE_DIRNAME
ଅକ୍ଷର *dirname(ଅଚଳ ଅକ୍ଷର *path);
#endif

#ifndef HAVE_FMT_SCALED
#define	FMT_SCALED_STRSIZE	7
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	fmt_scaled(long long ସଂଖ୍ୟା, ଅକ୍ଷର *result);
#endif

#ifndef HAVE_SCAN_SCALED
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	scan_scaled(ଅକ୍ଷର *, long long *);
#endif

#ଯଦି defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
ଅକ୍ଷର *inet_ntoa(ସଂରଚନା in_addr in);
#endif

#ifndef HAVE_INET_NTOP
ଅଚଳ ଅକ୍ଷର *inet_ntop(ପୂର୍ଣ୍ଣସଂଖ୍ୟା af, ଅଚଳ ଶୂନ୍ୟ *src, ଅକ୍ଷର *dst, socklen_t size);
#endif

#ifndef HAVE_INET_ATON
ପୂର୍ଣ୍ଣସଂଖ୍ୟା inet_aton(ଅଚଳ ଅକ୍ଷର *cp, ସଂରଚନା in_addr *addr);
#endif

#ifndef HAVE_STRSEP
ଅକ୍ଷର *strsep(ଅକ୍ଷର **stringp, ଅଚଳ ଅକ୍ଷର *delim);
#endif

#ifndef HAVE_SETPROCTITLE
ଶୂନ୍ୟ setproctitle(ଅଚଳ ଅକ୍ଷର *fmt, ...);
ଶୂନ୍ୟ compat_init_setproctitle(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର *argv[]);
#endif

#ifndef HAVE_GETGROUPLIST
ପୂର୍ଣ୍ଣସଂଖ୍ୟା getgrouplist(ଅଚଳ ଅକ୍ଷର *, gid_t, gid_t *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
#endif

#ଯଦି !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା BSDgetopt(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର * ଅଚଳ *argv, ଅଚଳ ଅକ୍ଷର *opts) __THROW;
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/getopt.h"
#endif

#ଯଦି ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# ଯଦି defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
ପୂର୍ଣ୍ଣସଂଖ୍ୟା readv(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା iovec *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
# endif

# ଯଦି defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
ପୂର୍ଣ୍ଣସଂଖ୍ୟା writev(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା iovec *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
# endif
#endif

/* Home grown routines */
#ଅନ୍ତର୍ଭାଵ "bsd-signal.h"
#ଅନ୍ତର୍ଭାଵ "bsd-misc.h"
#ଅନ୍ତର୍ଭାଵ "bsd-setres_id.h"
#ଅନ୍ତର୍ଭାଵ "bsd-statvfs.h"
#ଅନ୍ତର୍ଭାଵ "bsd-waitpid.h"
#ଅନ୍ତର୍ଭାଵ "bsd-poll.h"

#ଯଦି defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
ପୂର୍ଣ୍ଣସଂଖ୍ୟା getpeereid(ପୂର୍ଣ୍ଣସଂଖ୍ୟା , uid_t *, gid_t *);
#endif

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(ଶୂନ୍ୟ);
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_ARC4RANDOM_BUF
ଶୂନ୍ୟ arc4random_buf(ଶୂନ୍ୟ *, size_t);
#endif

#ifndef HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#endif

#ifndef HAVE_ASPRINTF
ପୂର୍ଣ୍ଣସଂଖ୍ୟା asprintf(ଅକ୍ଷର **, ଅଚଳ ଅକ୍ଷର *, ...);
#endif

#ifndef HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା openpty(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ଅକ୍ଷର *, ଅଚଳ ସଂରଚନା termios *,
    ଅଚଳ ସଂରଚନା winsize *);
#endif /* HAVE_OPENPTY */

#ifndef HAVE_SNPRINTF
ପୂର୍ଣ୍ଣସଂଖ୍ୟା snprintf(ଅକ୍ଷର *, size_t, SNPRINTF_CONST ଅକ୍ଷର *, ...);
#endif

#ifndef HAVE_STRTOLL
long long strtoll(ଅଚଳ ଅକ୍ଷର *, ଅକ୍ଷର **, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#endif

#ifndef HAVE_STRTOUL
unsigned long strtoul(ଅଚଳ ଅକ୍ଷର *, ଅକ୍ଷର **, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#endif

#ifndef HAVE_STRTOULL
unsigned long long strtoull(ଅଚଳ ଅକ୍ଷର *, ଅକ୍ଷର **, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(ଅଚଳ ଅକ୍ଷର *, long long, long long, ଅଚଳ ଅକ୍ଷର **);
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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mbtowc(wchar_t *, ଅଚଳ ଅକ୍ଷର*, size_t);
#endif

#ଯଦି !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
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
# ଅନ୍ୟଥା
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  ଅନ୍ୟଥା
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#endif

#ifndef HAVE_VASPRINTF
ପୂର୍ଣ୍ଣସଂଖ୍ୟା vasprintf(ଅକ୍ଷର **, ଅଚଳ ଅକ୍ଷର *, va_list);
#endif

#ifndef HAVE_VSNPRINTF
ପୂର୍ଣ୍ଣସଂଖ୍ୟା vsnprintf(ଅକ୍ଷର *, size_t, ଅଚଳ ଅକ୍ଷର *, va_list);
#endif

#ifndef HAVE_USER_FROM_UID
ଅକ୍ଷର *user_from_uid(uid_t, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#endif

#ifndef HAVE_GROUP_FROM_GID
ଅକ୍ଷର *group_from_gid(gid_t, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#endif

#ifndef HAVE_TIMINGSAFE_BCMP
ପୂର୍ଣ୍ଣସଂଖ୍ୟା timingsafe_bcmp(ଅଚଳ ଶୂନ୍ୟ *, ଅଚଳ ଶୂନ୍ୟ *, size_t);
#endif

#ifndef HAVE_BCRYPT_PBKDF
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	bcrypt_pbkdf(ଅଚଳ ଅକ୍ଷର *, size_t, ଅଚଳ uint8_t *, size_t,
    uint8_t *, size_t, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#endif

#ifndef HAVE_EXPLICIT_BZERO
ଶୂନ୍ୟ explicit_bzero(ଶୂନ୍ୟ *p, size_t n);
#endif

#ifndef HAVE_FREEZERO
ଶୂନ୍ୟ freezero(ଶୂନ୍ୟ *, size_t);
#endif

#ifndef HAVE_LOCALTIME_R
ସଂରଚନା tm *localtime_r(ଅଚଳ time_t *, ସଂରଚନା tm *);
#endif

#ifndef HAVE_TIMEGM
#ଅନ୍ତର୍ଭାଵ <time.h>
time_t timegm(ସଂରଚନା tm *);
#endif

ଅକ୍ଷର *xcrypt(ଅଚଳ ଅକ୍ଷର *password, ଅଚଳ ଅକ୍ଷର *salt);
ଅକ୍ଷର *shadow_pw(ସଂରଚନା passwd *pw);

/* rfc2553 socket API replacements */
#ଅନ୍ତର୍ଭାଵ "fake-rfc2553.h"

/* Routines for a single OS platform */
#ଅନ୍ତର୍ଭାଵ "bsd-cygwin_util.h"

#ଅନ୍ତର୍ଭାଵ "port-aix.h"
#ଅନ୍ତର୍ଭାଵ "port-irix.h"
#ଅନ୍ତର୍ଭାଵ "port-linux.h"
#ଅନ୍ତର୍ଭାଵ "port-solaris.h"
#ଅନ୍ତର୍ଭାଵ "port-net.h"
#ଅନ୍ତର୍ଭାଵ "port-uw.h"

/* _FORTIFY_SOURCE breaks FD_ISSET(n)/FD_SET(n) for n > FD_SETSIZE. Avoid. */
#ଯଦି defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# ଯଦି defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  ଯଦି __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, set)	kludge_FD_SET(n, set)
#   define FD_ISSET(n, set)	kludge_FD_ISSET(n, set)
ଶୂନ୍ୟ kludge_FD_SET(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, fd_set *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା kludge_FD_ISSET(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#endif /* _OPENBSD_COMPAT_H */
