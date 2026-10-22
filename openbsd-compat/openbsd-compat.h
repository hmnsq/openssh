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

#నిర్వచితం_కాకపోతే _OPENBSD_COMPAT_H
#నిర్వచించు _OPENBSD_COMPAT_H

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <pwd.h>

#అన్తర్భావ <sys/socket.h>

#అన్తర్భావ <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#అన్తర్భావ "base64.h"
#అన్తర్భావ "sigact.h"
#అన్తర్భావ "readpassphrase.h"
#అన్తర్భావ "vis.h"
#అన్తర్భావ "getrrsetbyname.h"
#అన్తర్భావ "sha1.h"
#అన్తర్భావ "bsd-sha2.h"
#అన్తర్భావ "md5.h"
#అన్తర్భావ "blf.h"
#అన్తర్భావ "fnmatch.h"

#నిర్వచితం_కాకపోతే __THROW
# ఒకవేళ defined __cplusplus
#  define __THROW throw()
# లేకపోతే
#  define __THROW
# endif
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_BASENAME
అక్షరం *basename(స్థిరరాశి అక్షరం *మార్గం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_BINDRESVPORT_SA
పూర్ణాంకం bindresvport_sa(పూర్ణాంకం sd, నిర్మాణం sockaddr *sa);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_CLOSEFROM
శూన్య closefrom(పూర్ణాంకం);
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
పూర్ణాంకం ftruncate(పూర్ణాంకం filedes, off_t నిడివి);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_GETLINE
#అన్తర్భావ <stdio.h>
ssize_t getline(అక్షరం **, కొలత_t *, FILE *);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_GETPAGESIZE
పూర్ణాంకం getpagesize(శూన్య);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_GETCWD
అక్షరం *getcwd(అక్షరం *pt, కొలత_t కొలత);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#నిర్వచించు getexecpath(a, b) (-1)
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_KILLPG
పూర్ణాంకం killpg(pid_t, పూర్ణాంకం);
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
శూన్య *memmem(స్థిరరాశి శూన్య *, కొలత_t, స్థిరరాశి శూన్య *, కొలత_t);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_REALLOCARRAY
శూన్య *reallocarray(శూన్య *, కొలత_t, కొలత_t);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_RECALLOCARRAY
శూన్య *recallocarray(శూన్య *, కొలత_t, కొలత_t, కొలత_t);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_RRESVPORT_AF
పూర్ణాంకం rresvport_af(పూర్ణాంకం *alport, sa_family_t af);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_STRLCPY
కొలత_t strlcpy(అక్షరం *dst, స్థిరరాశి అక్షరం *src, కొలత_t siz);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_STRLCAT
కొలత_t strlcat(అక్షరం *dst, స్థిరరాశి అక్షరం *src, కొలత_t siz);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_STRCASESTR
అక్షరం *strcasestr(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_STRNLEN
కొలత_t strnlen(స్థిరరాశి అక్షరం *, కొలత_t);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_STRNDUP
అక్షరం *strndup(స్థిరరాశి అక్షరం *s, కొలత_t n);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_SETENV
పూర్ణాంకం setenv(నమోదు స్థిరరాశి అక్షరం *name, నమోదు స్థిరరాశి అక్షరం *విలువ, పూర్ణాంకం rewrite);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_STRMODE
శూన్య strmode(పూర్ణాంకం బహుళకం, అక్షరం *p);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_STRPTIME
#అన్తర్భావ  <time.h>
అక్షరం *strptime(స్థిరరాశి అక్షరం *buf, స్థిరరాశి అక్షరం *fmt, నిర్మాణం tm *tm);
#అయితే_ముగింపు

#ఒకవేళ !defined(HAVE_MKDTEMP)
పూర్ణాంకం mkstemps(అక్షరం *మార్గం, పూర్ణాంకం slen);
పూర్ణాంకం mkstemp(అక్షరం *మార్గం);
అక్షరం *mkdtemp(అక్షరం *మార్గం);
#అయితే_ముగింపు

#నిర్వచించు mkstemp(x) _ssh_mkstemp(x)
పూర్ణాంకం _ssh_mkstemp(అక్షరం *);

#నిర్వచితం_కాకపోతే HAVE_DAEMON
పూర్ణాంకం daemon(పూర్ణాంకం nochdir, పూర్ణాంకం noclose);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_DIRNAME
అక్షరం *dirname(స్థిరరాశి అక్షరం *మార్గం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_FMT_SCALED
#నిర్వచించు	FMT_SCALED_STRSIZE	7
పూర్ణాంకం	fmt_scaled(దీర్ఘ దీర్ఘ సంఖ్య, అక్షరం *ఫలితం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_పరిశీలన_SCALED
పూర్ణాంకం	పరిశీలన_scaled(అక్షరం *, దీర్ఘ దీర్ఘ *);
#అయితే_ముగింపు

#ఒకవేళ defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
అక్షరం *inet_ntoa(నిర్మాణం in_addr లోపల);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_INET_NTOP
స్థిరరాశి అక్షరం *inet_ntop(పూర్ణాంకం af, స్థిరరాశి శూన్య *src, అక్షరం *dst, socklen_t కొలత);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_INET_ATON
పూర్ణాంకం inet_aton(స్థిరరాశి అక్షరం *cp, నిర్మాణం in_addr *addr);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_STRSEP
అక్షరం *strsep(అక్షరం **stringp, స్థిరరాశి అక్షరం *delim);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_SETPROCTITLE
శూన్య setproctitle(స్థిరరాశి అక్షరం *fmt, ...);
శూన్య compat_init_setproctitle(పూర్ణాంకం argc, అక్షరం *argv[]);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_GETGROUPLIST
పూర్ణాంకం getgrouplist(స్థిరరాశి అక్షరం *, gid_t, gid_t *, పూర్ణాంకం *);
#అయితే_ముగింపు

#ఒకవేళ !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
పూర్ణాంకం BSDgetopt(పూర్ణాంకం argc, అక్షరం * స్థిరరాశి *argv, స్థిరరాశి అక్షరం *opts) __THROW;
#అన్తర్భావ "openbsd-compat/getopt.h"
#అయితే_ముగింపు

#ఒకవేళ ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# ఒకవేళ defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
పూర్ణాంకం readv(పూర్ణాంకం, నిర్మాణం iovec *, పూర్ణాంకం);
# endif

# ఒకవేళ defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
పూర్ణాంకం writev(పూర్ణాంకం, నిర్మాణం iovec *, పూర్ణాంకం);
# endif
#అయితే_ముగింపు

/* Home grown routines */
#అన్తర్భావ "bsd-signal.h"
#అన్తర్భావ "bsd-misc.h"
#అన్తర్భావ "bsd-setres_id.h"
#అన్తర్భావ "bsd-statvfs.h"
#అన్తర్భావ "bsd-waitpid.h"
#అన్తర్భావ "bsd-poll.h"

#ఒకవేళ defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
పూర్ణాంకం getpeereid(పూర్ణాంకం , uid_t *, gid_t *);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_ARC4RANDOM
uint32_t arc4random(శూన్య);
#అయితే_ముగింపు /* !HAVE_ARC4RANDOM */

#నిర్వచితం_కాకపోతే HAVE_ARC4RANDOM_BUF
శూన్య arc4random_buf(శూన్య *, కొలత_t);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_ARC4_RANDOM_ఏకరీతి
uint32_t arc4random_ఏకరీతి(uint32_t);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_ASPRINTF
పూర్ణాంకం asprintf(అక్షరం **, స్థిరరాశి అక్షరం *, ...);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
పూర్ణాంకం openpty(పూర్ణాంకం *, పూర్ణాంకం *, అక్షరం *, స్థిరరాశి నిర్మాణం termios *,
    స్థిరరాశి నిర్మాణం winsize *);
#అయితే_ముగింపు /* HAVE_OPENPTY */

#నిర్వచితం_కాకపోతే HAVE_SNPRINTF
పూర్ణాంకం snprintf(అక్షరం *, కొలత_t, SNPRINTF_CONST అక్షరం *, ...);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_STRTOLL
దీర్ఘ దీర్ఘ strtoll(స్థిరరాశి అక్షరం *, అక్షరం **, పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_STRTOUL
గుర్తులేని దీర్ఘ strtoul(స్థిరరాశి అక్షరం *, అక్షరం **, పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_STRTOULL
గుర్తులేని దీర్ఘ దీర్ఘ strtoull(స్థిరరాశి అక్షరం *, అక్షరం **, పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_STRTONUM
దీర్ఘ దీర్ఘ strtonum(స్థిరరాశి అక్షరం *, దీర్ఘ దీర్ఘ, దీర్ఘ దీర్ఘ, స్థిరరాశి అక్షరం **);
#అయితే_ముగింపు

/* multibyte character support */
#నిర్వచితం_కాకపోతే HAVE_MBLEN
# define mblen(x, y)	(1)
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_WCWIDTH
# define wcwidth(x)	(((x) >= 0x20 && (x) <= 0x7e) ? 1 : -1)
/* force our no-op nl_langinfo and mbtowc */
# undef HAVE_NL_LANGINFO
# undef HAVE_MBTOWC
# undef HAVE_LANGINFO_H
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_NL_LANGINFO
# define nl_langinfo(x)	""
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_MBTOWC
పూర్ణాంకం mbtowc(wchar_t *, స్థిరరాశి అక్షరం*, కొలత_t);
#అయితే_ముగింపు

#ఒకవేళ !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
# include <stdarg.h>
#అయితే_ముగింపు

/*
 * Some platforms unconditionally undefine va_copy() so we define VA_COPY()
 * instead.  This is known to be the case on at least some configurations of
 * AIX with the xlc compiler.
 */
#నిర్వచితం_కాకపోతే VA_COPY
# ifdef HAVE_VA_COPY
#  define VA_COPY(dest, src) va_copy(dest, src)
# లేకపోతే
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  లేకపోతే
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_VASPRINTF
పూర్ణాంకం vasprintf(అక్షరం **, స్థిరరాశి అక్షరం *, va_list);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_VSNPRINTF
పూర్ణాంకం vsnprintf(అక్షరం *, కొలత_t, స్థిరరాశి అక్షరం *, va_list);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_USER_FROM_UID
అక్షరం *user_from_uid(uid_t, పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_సమూహం_FROM_GID
అక్షరం *సమూహం_from_gid(gid_t, పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_TIMINGSAFE_BCMP
పూర్ణాంకం timingsafe_bcmp(స్థిరరాశి శూన్య *, స్థిరరాశి శూన్య *, కొలత_t);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_BCRYPT_PBKDF
పూర్ణాంకం	bcrypt_pbkdf(స్థిరరాశి అక్షరం *, కొలత_t, స్థిరరాశి uint8_t *, కొలత_t,
    uint8_t *, కొలత_t, గుర్తులేని పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_EXPLICIT_BZERO
శూన్య explicit_bzero(శూన్య *p, కొలత_t n);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_FREEZERO
శూన్య freezero(శూన్య *, కొలత_t);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_LOCALTIME_R
నిర్మాణం tm *localtime_r(స్థిరరాశి time_t *, నిర్మాణం tm *);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_TIMEGM
#అన్తర్భావ <time.h>
time_t timegm(నిర్మాణం tm *);
#అయితే_ముగింపు

అక్షరం *xcrypt(స్థిరరాశి అక్షరం *password, స్థిరరాశి అక్షరం *salt);
అక్షరం *shadow_pw(నిర్మాణం passwd *pw);

/* rfc2553 socket API replacements */
#అన్తర్భావ "fake-rfc2553.h"

/* Routines for a single OS platform */
#అన్తర్భావ "bsd-cygwin_util.h"

#అన్తర్భావ "port-aix.h"
#అన్తర్భావ "port-irix.h"
#అన్తర్భావ "port-linux.h"
#అన్తర్భావ "port-solaris.h"
#అన్తర్భావ "port-net.h"
#అన్తర్భావ "port-uw.h"

/* _FORTIFY_SOURCE breaks FD_ISSET(n)/FD_SET(n) for n > FD_SETSIZE. Avoid. */
#ఒకవేళ defined(HAVE_FEATURES_H) && defined(FORTIFY_ఆధారం)
# include <features.h>
# ఒకవేళ defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  ఒకవేళ __GLIBC_PREREQ(2, 15) && (FORTIFY_ఆధారం > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, సమితి)	kludge_FD_సమితి(n, సమితి)
#   define FD_ISSET(n, సమితి)	kludge_FD_ISSET(n, సమితి)
శూన్య kludge_FD_సమితి(పూర్ణాంకం, fd_set *);
పూర్ణాంకం kludge_FD_ISSET(పూర్ణాంకం, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#అయితే_ముగింపు /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#అయితే_ముగింపు /* _OPENBSD_COMPAT_H */
