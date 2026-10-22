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

#اگر_تعریف_نشده _OPENBSD_COMPAT_H
#تعریف_کن _OPENBSD_COMPAT_H

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

#اگر_تعریف_نشده __THROW
# إذا defined __cplusplus
#  define __THROW throw()
# وإلا
#  define __THROW
# endif
#پایان_اگر

#إذا defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#پایان_اگر

#اگر_تعریف_نشده HAVE_BASENAME
حرف *basename(ثابت حرف *مسیر);
#پایان_اگر

#اگر_تعریف_نشده HAVE_BINDRESVPORT_SA
صحيح bindresvport_sa(صحيح sd, بنية sockaddr *sa);
#پایان_اگر

#اگر_تعریف_نشده HAVE_CLOSEFROM
فراغ closefrom(صحيح);
#پایان_اگر

#إذا defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
صحيح ftruncate(صحيح filedes, off_t درازی);
#پایان_اگر

#اگر_تعریف_نشده HAVE_GETLINE
#ضمن <stdio.h>
ssize_t getline(حرف **, اندازه_t *, FILE *);
#پایان_اگر

#اگر_تعریف_نشده HAVE_GETPAGESIZE
صحيح getpagesize(فراغ);
#پایان_اگر

#اگر_تعریف_نشده HAVE_GETCWD
حرف *getcwd(حرف *pt, اندازه_t اندازه);
#پایان_اگر

#اگر_تعریف_نشده HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#تعریف_کن getexecpath(a, b) (-1)
#پایان_اگر

#اگر_تعریف_نشده HAVE_KILLPG
صحيح killpg(pid_t, صحيح);
#پایان_اگر

#إذا defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
فراغ *memmem(ثابت فراغ *, اندازه_t, ثابت فراغ *, اندازه_t);
#پایان_اگر

#اگر_تعریف_نشده HAVE_REALLOCARRAY
فراغ *reallocarray(فراغ *, اندازه_t, اندازه_t);
#پایان_اگر

#اگر_تعریف_نشده HAVE_RECALLOCARRAY
فراغ *recallocarray(فراغ *, اندازه_t, اندازه_t, اندازه_t);
#پایان_اگر

#اگر_تعریف_نشده HAVE_RRESVPORT_AF
صحيح rresvport_af(صحيح *alport, sa_family_t af);
#پایان_اگر

#اگر_تعریف_نشده HAVE_STRLCPY
اندازه_t strlcpy(حرف *dst, ثابت حرف *src, اندازه_t siz);
#پایان_اگر

#اگر_تعریف_نشده HAVE_STRLCAT
اندازه_t strlcat(حرف *dst, ثابت حرف *src, اندازه_t siz);
#پایان_اگر

#اگر_تعریف_نشده HAVE_STRCASESTR
حرف *strcasestr(ثابت حرف *, ثابت حرف *);
#پایان_اگر

#اگر_تعریف_نشده HAVE_STRNLEN
اندازه_t strnlen(ثابت حرف *, اندازه_t);
#پایان_اگر

#اگر_تعریف_نشده HAVE_STRNDUP
حرف *strndup(ثابت حرف *s, اندازه_t n);
#پایان_اگر

#اگر_تعریف_نشده HAVE_SETENV
صحيح setenv(سجل ثابت حرف *name, سجل ثابت حرف *مقدار, صحيح rewrite);
#پایان_اگر

#اگر_تعریف_نشده HAVE_STRMODE
فراغ strmode(صحيح نما, حرف *p);
#پایان_اگر

#اگر_تعریف_نشده HAVE_STRPTIME
#ضمن  <time.h>
حرف *strptime(ثابت حرف *buf, ثابت حرف *fmt, بنية tm *tm);
#پایان_اگر

#إذا !defined(HAVE_MKDTEMP)
صحيح mkstemps(حرف *مسیر, صحيح slen);
صحيح mkstemp(حرف *مسیر);
حرف *mkdtemp(حرف *مسیر);
#پایان_اگر

#تعریف_کن mkstemp(x) _ssh_mkstemp(x)
صحيح _ssh_mkstemp(حرف *);

#اگر_تعریف_نشده HAVE_DAEMON
صحيح daemon(صحيح nochdir, صحيح noclose);
#پایان_اگر

#اگر_تعریف_نشده HAVE_DIRNAME
حرف *dirname(ثابت حرف *مسیر);
#پایان_اگر

#اگر_تعریف_نشده HAVE_FMT_SCALED
#تعریف_کن	FMT_SCALED_STRSIZE	7
صحيح	fmt_scaled(دراز دراز عدد, حرف *نتیجه);
#پایان_اگر

#اگر_تعریف_نشده HAVE_پیمایش_SCALED
صحيح	پیمایش_scaled(حرف *, دراز دراز *);
#پایان_اگر

#إذا defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
حرف *inet_ntoa(بنية in_addr درون);
#پایان_اگر

#اگر_تعریف_نشده HAVE_INET_NTOP
ثابت حرف *inet_ntop(صحيح af, ثابت فراغ *src, حرف *dst, socklen_t اندازه);
#پایان_اگر

#اگر_تعریف_نشده HAVE_INET_ATON
صحيح inet_aton(ثابت حرف *cp, بنية in_addr *addr);
#پایان_اگر

#اگر_تعریف_نشده HAVE_STRSEP
حرف *strsep(حرف **stringp, ثابت حرف *delim);
#پایان_اگر

#اگر_تعریف_نشده HAVE_SETPROCTITLE
فراغ setproctitle(ثابت حرف *fmt, ...);
فراغ compat_init_setproctitle(صحيح argc, حرف *argv[]);
#پایان_اگر

#اگر_تعریف_نشده HAVE_GETGROUPLIST
صحيح getgrouplist(ثابت حرف *, gid_t, gid_t *, صحيح *);
#پایان_اگر

#إذا !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
صحيح BSDgetopt(صحيح argc, حرف * ثابت *argv, ثابت حرف *opts) __THROW;
#ضمن "openbsd-compat/getopt.h"
#پایان_اگر

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
#پایان_اگر

/* Home grown routines */
#ضمن "bsd-signal.h"
#ضمن "bsd-misc.h"
#ضمن "bsd-setres_id.h"
#ضمن "bsd-statvfs.h"
#ضمن "bsd-waitpid.h"
#ضمن "bsd-poll.h"

#إذا defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
صحيح getpeereid(صحيح , uid_t *, gid_t *);
#پایان_اگر

#اگر_تعریف_نشده HAVE_ARC4RANDOM
uint32_t arc4random(فراغ);
#پایان_اگر /* !HAVE_ARC4RANDOM */

#اگر_تعریف_نشده HAVE_ARC4RANDOM_BUF
فراغ arc4random_buf(فراغ *, اندازه_t);
#پایان_اگر

#اگر_تعریف_نشده HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#پایان_اگر

#اگر_تعریف_نشده HAVE_ARC4_RANDOM_یکنواخت
uint32_t arc4random_یکنواخت(uint32_t);
#پایان_اگر

#اگر_تعریف_نشده HAVE_ASPRINTF
صحيح asprintf(حرف **, ثابت حرف *, ...);
#پایان_اگر

#اگر_تعریف_نشده HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
صحيح openpty(صحيح *, صحيح *, حرف *, ثابت بنية termios *,
    ثابت بنية winsize *);
#پایان_اگر /* HAVE_OPENPTY */

#اگر_تعریف_نشده HAVE_SNPRINTF
صحيح snprintf(حرف *, اندازه_t, SNPRINTF_CONST حرف *, ...);
#پایان_اگر

#اگر_تعریف_نشده HAVE_STRTOLL
دراز دراز strtoll(ثابت حرف *, حرف **, صحيح);
#پایان_اگر

#اگر_تعریف_نشده HAVE_STRTOUL
بیعلامت دراز strtoul(ثابت حرف *, حرف **, صحيح);
#پایان_اگر

#اگر_تعریف_نشده HAVE_STRTOULL
بیعلامت دراز دراز strtoull(ثابت حرف *, حرف **, صحيح);
#پایان_اگر

#اگر_تعریف_نشده HAVE_STRTONUM
دراز دراز strtonum(ثابت حرف *, دراز دراز, دراز دراز, ثابت حرف **);
#پایان_اگر

/* multibyte character support */
#اگر_تعریف_نشده HAVE_MBLEN
# define mblen(x, y)	(1)
#پایان_اگر

#اگر_تعریف_نشده HAVE_WCWIDTH
# define wcwidth(x)	(((x) >= 0x20 && (x) <= 0x7e) ? 1 : -1)
/* force our no-op nl_langinfo and mbtowc */
# undef HAVE_NL_LANGINFO
# undef HAVE_MBTOWC
# undef HAVE_LANGINFO_H
#پایان_اگر

#اگر_تعریف_نشده HAVE_NL_LANGINFO
# define nl_langinfo(x)	""
#پایان_اگر

#اگر_تعریف_نشده HAVE_MBTOWC
صحيح mbtowc(wchar_t *, ثابت حرف*, اندازه_t);
#پایان_اگر

#إذا !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
# include <stdarg.h>
#پایان_اگر

/*
 * Some platforms unconditionally undefine va_copy() so we define VA_COPY()
 * instead.  This is known to be the case on at least some configurations of
 * AIX with the xlc compiler.
 */
#اگر_تعریف_نشده VA_COPY
# ifdef HAVE_VA_COPY
#  define VA_COPY(dest, src) va_copy(dest, src)
# وإلا
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  وإلا
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#پایان_اگر

#اگر_تعریف_نشده HAVE_VASPRINTF
صحيح vasprintf(حرف **, ثابت حرف *, va_list);
#پایان_اگر

#اگر_تعریف_نشده HAVE_VSNPRINTF
صحيح vsnprintf(حرف *, اندازه_t, ثابت حرف *, va_list);
#پایان_اگر

#اگر_تعریف_نشده HAVE_USER_FROM_UID
حرف *user_from_uid(uid_t, صحيح);
#پایان_اگر

#اگر_تعریف_نشده HAVE_گروه_FROM_GID
حرف *گروه_from_gid(gid_t, صحيح);
#پایان_اگر

#اگر_تعریف_نشده HAVE_TIMINGSAFE_BCMP
صحيح timingsafe_bcmp(ثابت فراغ *, ثابت فراغ *, اندازه_t);
#پایان_اگر

#اگر_تعریف_نشده HAVE_BCRYPT_PBKDF
صحيح	bcrypt_pbkdf(ثابت حرف *, اندازه_t, ثابت uint8_t *, اندازه_t,
    uint8_t *, اندازه_t, بیعلامت صحيح);
#پایان_اگر

#اگر_تعریف_نشده HAVE_EXPLICIT_BZERO
فراغ explicit_bzero(فراغ *p, اندازه_t n);
#پایان_اگر

#اگر_تعریف_نشده HAVE_FREEZERO
فراغ freezero(فراغ *, اندازه_t);
#پایان_اگر

#اگر_تعریف_نشده HAVE_LOCALTIME_R
بنية tm *localtime_r(ثابت time_t *, بنية tm *);
#پایان_اگر

#اگر_تعریف_نشده HAVE_TIMEGM
#ضمن <time.h>
time_t timegm(بنية tm *);
#پایان_اگر

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
#إذا defined(HAVE_FEATURES_H) && defined(FORTIFY_منبع)
# include <features.h>
# إذا defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  إذا __GLIBC_PREREQ(2, 15) && (FORTIFY_منبع > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, مجموعه)	kludge_FD_مجموعه(n, مجموعه)
#   define FD_ISSET(n, مجموعه)	kludge_FD_ISSET(n, مجموعه)
فراغ kludge_FD_مجموعه(صحيح, fd_set *);
صحيح kludge_FD_ISSET(صحيح, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#پایان_اگر /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#پایان_اگر /* _OPENBSD_COMPAT_H */
