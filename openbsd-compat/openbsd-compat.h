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

#جے_بنا_تعریف _OPENBSD_COMPAT_H
#تعریف_کرو _OPENBSD_COMPAT_H

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

#جے_بنا_تعریف __THROW
# إذا defined __cplusplus
#  define __THROW throw()
# وإلا
#  define __THROW
# endif
#جے_انت

#إذا defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#جے_انت

#جے_بنا_تعریف HAVE_BASENAME
حرف *basename(ثابت حرف *رستہ);
#جے_انت

#جے_بنا_تعریف HAVE_BINDRESVPORT_SA
صحيح bindresvport_sa(صحيح sd, بنية sockaddr *sa);
#جے_انت

#جے_بنا_تعریف HAVE_CLOSEFROM
فراغ closefrom(صحيح);
#جے_انت

#إذا defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
صحيح ftruncate(صحيح filedes, off_t لمائی);
#جے_انت

#جے_بنا_تعریف HAVE_GETLINE
#ضمن <stdio.h>
ssize_t getline(حرف **, ناپ_t *, FILE *);
#جے_انت

#جے_بنا_تعریف HAVE_GETPAGESIZE
صحيح getpagesize(فراغ);
#جے_انت

#جے_بنا_تعریف HAVE_GETCWD
حرف *getcwd(حرف *pt, ناپ_t ناپ);
#جے_انت

#جے_بنا_تعریف HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#تعریف_کرو getexecpath(a, b) (-1)
#جے_انت

#جے_بنا_تعریف HAVE_KILLPG
صحيح killpg(pid_t, صحيح);
#جے_انت

#إذا defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
فراغ *memmem(ثابت فراغ *, ناپ_t, ثابت فراغ *, ناپ_t);
#جے_انت

#جے_بنا_تعریف HAVE_REALLOCARRAY
فراغ *reallocarray(فراغ *, ناپ_t, ناپ_t);
#جے_انت

#جے_بنا_تعریف HAVE_RECALLOCARRAY
فراغ *recallocarray(فراغ *, ناپ_t, ناپ_t, ناپ_t);
#جے_انت

#جے_بنا_تعریف HAVE_RRESVPORT_AF
صحيح rresvport_af(صحيح *alport, sa_family_t af);
#جے_انت

#جے_بنا_تعریف HAVE_STRLCPY
ناپ_t strlcpy(حرف *dst, ثابت حرف *src, ناپ_t siz);
#جے_انت

#جے_بنا_تعریف HAVE_STRLCAT
ناپ_t strlcat(حرف *dst, ثابت حرف *src, ناپ_t siz);
#جے_انت

#جے_بنا_تعریف HAVE_STRCASESTR
حرف *strcasestr(ثابت حرف *, ثابت حرف *);
#جے_انت

#جے_بنا_تعریف HAVE_STRNLEN
ناپ_t strnlen(ثابت حرف *, ناپ_t);
#جے_انت

#جے_بنا_تعریف HAVE_STRNDUP
حرف *strndup(ثابت حرف *s, ناپ_t n);
#جے_انت

#جے_بنا_تعریف HAVE_SETENV
صحيح setenv(سجل ثابت حرف *name, سجل ثابت حرف *قدر, صحيح rewrite);
#جے_انت

#جے_بنا_تعریف HAVE_STRMODE
فراغ strmode(صحيح منوال, حرف *p);
#جے_انت

#جے_بنا_تعریف HAVE_STRPTIME
#ضمن  <time.h>
حرف *strptime(ثابت حرف *buf, ثابت حرف *fmt, بنية tm *tm);
#جے_انت

#إذا !defined(HAVE_MKDTEMP)
صحيح mkstemps(حرف *رستہ, صحيح slen);
صحيح mkstemp(حرف *رستہ);
حرف *mkdtemp(حرف *رستہ);
#جے_انت

#تعریف_کرو mkstemp(x) _ssh_mkstemp(x)
صحيح _ssh_mkstemp(حرف *);

#جے_بنا_تعریف HAVE_DAEMON
صحيح daemon(صحيح nochdir, صحيح noclose);
#جے_انت

#جے_بنا_تعریف HAVE_DIRNAME
حرف *dirname(ثابت حرف *رستہ);
#جے_انت

#جے_بنا_تعریف HAVE_FMT_SCALED
#تعریف_کرو	FMT_SCALED_STRSIZE	7
صحيح	fmt_scaled(لما لما نمبر, حرف *نتیجہ);
#جے_انت

#جے_بنا_تعریف HAVE_جانچ_SCALED
صحيح	جانچ_scaled(حرف *, لما لما *);
#جے_انت

#إذا defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
حرف *inet_ntoa(بنية in_addr وچ);
#جے_انت

#جے_بنا_تعریف HAVE_INET_NTOP
ثابت حرف *inet_ntop(صحيح af, ثابت فراغ *src, حرف *dst, socklen_t ناپ);
#جے_انت

#جے_بنا_تعریف HAVE_INET_ATON
صحيح inet_aton(ثابت حرف *cp, بنية in_addr *addr);
#جے_انت

#جے_بنا_تعریف HAVE_STRSEP
حرف *strsep(حرف **stringp, ثابت حرف *delim);
#جے_انت

#جے_بنا_تعریف HAVE_SETPROCTITLE
فراغ setproctitle(ثابت حرف *fmt, ...);
فراغ compat_init_setproctitle(صحيح argc, حرف *argv[]);
#جے_انت

#جے_بنا_تعریف HAVE_GETGROUPLIST
صحيح getgrouplist(ثابت حرف *, gid_t, gid_t *, صحيح *);
#جے_انت

#إذا !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
صحيح BSDgetopt(صحيح argc, حرف * ثابت *argv, ثابت حرف *opts) __THROW;
#ضمن "openbsd-compat/getopt.h"
#جے_انت

#إذا ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# إذا defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
صحيح readv(صحيح, بنية iovec *, صحيح);
# endif

# إذا defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
صحيح writev(صحيح, بنية iovec *, صحيح);
# endif
#جے_انت

/* Home grown routines */
#ضمن "bsd-signal.h"
#ضمن "bsd-misc.h"
#ضمن "bsd-setres_id.h"
#ضمن "bsd-statvfs.h"
#ضمن "bsd-waitpid.h"
#ضمن "bsd-poll.h"

#إذا defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
صحيح getpeereid(صحيح , uid_t *, gid_t *);
#جے_انت

#جے_بنا_تعریف HAVE_ARC4RANDOM
uint32_t arc4random(فراغ);
#جے_انت /* !HAVE_ARC4RANDOM */

#جے_بنا_تعریف HAVE_ARC4RANDOM_BUF
فراغ arc4random_buf(فراغ *, ناپ_t);
#جے_انت

#جے_بنا_تعریف HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#جے_انت

#جے_بنا_تعریف HAVE_ARC4_RANDOM_اکسار
uint32_t arc4random_اکسار(uint32_t);
#جے_انت

#جے_بنا_تعریف HAVE_ASPRINTF
صحيح asprintf(حرف **, ثابت حرف *, ...);
#جے_انت

#جے_بنا_تعریف HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
صحيح openpty(صحيح *, صحيح *, حرف *, ثابت بنية termios *,
    ثابت بنية winsize *);
#جے_انت /* HAVE_OPENPTY */

#جے_بنا_تعریف HAVE_SNPRINTF
صحيح snprintf(حرف *, ناپ_t, SNPRINTF_CONST حرف *, ...);
#جے_انت

#جے_بنا_تعریف HAVE_STRTOLL
لما لما strtoll(ثابت حرف *, حرف **, صحيح);
#جے_انت

#جے_بنا_تعریف HAVE_STRTOUL
بنانشانی لما strtoul(ثابت حرف *, حرف **, صحيح);
#جے_انت

#جے_بنا_تعریف HAVE_STRTOULL
بنانشانی لما لما strtoull(ثابت حرف *, حرف **, صحيح);
#جے_انت

#جے_بنا_تعریف HAVE_STRTONUM
لما لما strtonum(ثابت حرف *, لما لما, لما لما, ثابت حرف **);
#جے_انت

/* multibyte character support */
#جے_بنا_تعریف HAVE_MBLEN
# define mblen(x, y)	(1)
#جے_انت

#جے_بنا_تعریف HAVE_WCWIDTH
# define wcwidth(x)	(((x) >= 0x20 && (x) <= 0x7e) ? 1 : -1)
/* force our no-op nl_langinfo and mbtowc */
# undef HAVE_NL_LANGINFO
# undef HAVE_MBTOWC
# undef HAVE_LANGINFO_H
#جے_انت

#جے_بنا_تعریف HAVE_NL_LANGINFO
# define nl_langinfo(x)	""
#جے_انت

#جے_بنا_تعریف HAVE_MBTOWC
صحيح mbtowc(wchar_t *, ثابت حرف*, ناپ_t);
#جے_انت

#إذا !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
# include <stdarg.h>
#جے_انت

/*
 * Some platforms unconditionally undefine va_copy() so we define VA_COPY()
 * instead.  This is known to be the case on at least some configurations of
 * AIX with the xlc compiler.
 */
#جے_بنا_تعریف VA_COPY
# ifdef HAVE_VA_COPY
#  define VA_COPY(dest, src) va_copy(dest, src)
# وإلا
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  وإلا
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#جے_انت

#جے_بنا_تعریف HAVE_VASPRINTF
صحيح vasprintf(حرف **, ثابت حرف *, va_list);
#جے_انت

#جے_بنا_تعریف HAVE_VSNPRINTF
صحيح vsnprintf(حرف *, ناپ_t, ثابت حرف *, va_list);
#جے_انت

#جے_بنا_تعریف HAVE_USER_FROM_UID
حرف *user_from_uid(uid_t, صحيح);
#جے_انت

#جے_بنا_تعریف HAVE_گروہ_FROM_GID
حرف *گروہ_from_gid(gid_t, صحيح);
#جے_انت

#جے_بنا_تعریف HAVE_TIMINGSAFE_BCMP
صحيح timingsafe_bcmp(ثابت فراغ *, ثابت فراغ *, ناپ_t);
#جے_انت

#جے_بنا_تعریف HAVE_BCRYPT_PBKDF
صحيح	bcrypt_pbkdf(ثابت حرف *, ناپ_t, ثابت uint8_t *, ناپ_t,
    uint8_t *, ناپ_t, بنانشانی صحيح);
#جے_انت

#جے_بنا_تعریف HAVE_EXPLICIT_BZERO
فراغ explicit_bzero(فراغ *p, ناپ_t n);
#جے_انت

#جے_بنا_تعریف HAVE_FREEZERO
فراغ freezero(فراغ *, ناپ_t);
#جے_انت

#جے_بنا_تعریف HAVE_LOCALTIME_R
بنية tm *localtime_r(ثابت time_t *, بنية tm *);
#جے_انت

#جے_بنا_تعریف HAVE_TIMEGM
#ضمن <time.h>
time_t timegm(بنية tm *);
#جے_انت

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
#إذا defined(HAVE_FEATURES_H) && defined(FORTIFY_سروت)
# include <features.h>
# إذا defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  إذا __GLIBC_PREREQ(2, 15) && (FORTIFY_سروت > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, سیٹ)	kludge_FD_سیٹ(n, سیٹ)
#   define FD_ISSET(n, سیٹ)	kludge_FD_ISSET(n, سیٹ)
فراغ kludge_FD_سیٹ(صحيح, fd_set *);
صحيح kludge_FD_ISSET(صحيح, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#جے_انت /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#جے_انت /* _OPENBSD_COMPAT_H */
