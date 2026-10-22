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

#جيڪڏهن_وصف_نه_ٿيل _OPENBSD_COMPAT_H
#وصف_ڪريو _OPENBSD_COMPAT_H

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

#جيڪڏهن_وصف_نه_ٿيل __THROW
# إذا defined __cplusplus
#  define __THROW throw()
# وإلا
#  define __THROW
# endif
#جيڪڏهن_پورو

#إذا defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_BASENAME
حرف *basename(ثابت حرف *رستو);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_BINDRESVPORT_SA
صحيح bindresvport_sa(صحيح sd, بنية sockaddr *sa);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_CLOSEFROM
فراغ closefrom(صحيح);
#جيڪڏهن_پورو

#إذا defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
صحيح ftruncate(صحيح filedes, off_t ڊيگهائي);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_GETLINE
#ضمن <stdio.h>
ssize_t getline(حرف **, سائيز_t *, FILE *);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_GETPAGESIZE
صحيح getpagesize(فراغ);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_GETCWD
حرف *getcwd(حرف *pt, سائيز_t سائيز);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#وصف_ڪريو getexecpath(a, b) (-1)
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_KILLPG
صحيح killpg(pid_t, صحيح);
#جيڪڏهن_پورو

#إذا defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
فراغ *memmem(ثابت فراغ *, سائيز_t, ثابت فراغ *, سائيز_t);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_REALLOCARRAY
فراغ *reallocarray(فراغ *, سائيز_t, سائيز_t);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_RECALLOCARRAY
فراغ *recallocarray(فراغ *, سائيز_t, سائيز_t, سائيز_t);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_RRESVPORT_AF
صحيح rresvport_af(صحيح *alport, sa_family_t af);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRLCPY
سائيز_t strlcpy(حرف *dst, ثابت حرف *src, سائيز_t siz);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRLCAT
سائيز_t strlcat(حرف *dst, ثابت حرف *src, سائيز_t siz);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRCASESTR
حرف *strcasestr(ثابت حرف *, ثابت حرف *);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRNLEN
سائيز_t strnlen(ثابت حرف *, سائيز_t);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRNDUP
حرف *strndup(ثابت حرف *s, سائيز_t n);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_SETENV
صحيح setenv(سجل ثابت حرف *name, سجل ثابت حرف *قدر, صحيح rewrite);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRMODE
فراغ strmode(صحيح گهڻائي, حرف *p);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRPTIME
#ضمن  <time.h>
حرف *strptime(ثابت حرف *buf, ثابت حرف *fmt, بنية tm *tm);
#جيڪڏهن_پورو

#إذا !defined(HAVE_MKDTEMP)
صحيح mkstemps(حرف *رستو, صحيح slen);
صحيح mkstemp(حرف *رستو);
حرف *mkdtemp(حرف *رستو);
#جيڪڏهن_پورو

#وصف_ڪريو mkstemp(x) _ssh_mkstemp(x)
صحيح _ssh_mkstemp(حرف *);

#جيڪڏهن_وصف_نه_ٿيل HAVE_DAEMON
صحيح daemon(صحيح nochdir, صحيح noclose);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_DIRNAME
حرف *dirname(ثابت حرف *رستو);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_FMT_SCALED
#وصف_ڪريو	FMT_SCALED_STRSIZE	7
صحيح	fmt_scaled(ڊگهو ڊگهو عدد, حرف *نتيجو);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_جاچ_SCALED
صحيح	جاچ_scaled(حرف *, ڊگهو ڊگهو *);
#جيڪڏهن_پورو

#إذا defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
حرف *inet_ntoa(بنية in_addr اندريون);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_INET_NTOP
ثابت حرف *inet_ntop(صحيح af, ثابت فراغ *src, حرف *dst, socklen_t سائيز);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_INET_ATON
صحيح inet_aton(ثابت حرف *cp, بنية in_addr *addr);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRSEP
حرف *strsep(حرف **stringp, ثابت حرف *delim);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_SETPROCTITLE
فراغ setproctitle(ثابت حرف *fmt, ...);
فراغ compat_init_setproctitle(صحيح argc, حرف *argv[]);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_GETGROUPLIST
صحيح getgrouplist(ثابت حرف *, gid_t, gid_t *, صحيح *);
#جيڪڏهن_پورو

#إذا !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
صحيح BSDgetopt(صحيح argc, حرف * ثابت *argv, ثابت حرف *opts) __THROW;
#ضمن "openbsd-compat/getopt.h"
#جيڪڏهن_پورو

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
#جيڪڏهن_پورو

/* Home grown routines */
#ضمن "bsd-signal.h"
#ضمن "bsd-misc.h"
#ضمن "bsd-setres_id.h"
#ضمن "bsd-statvfs.h"
#ضمن "bsd-waitpid.h"
#ضمن "bsd-poll.h"

#إذا defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
صحيح getpeereid(صحيح , uid_t *, gid_t *);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_ARC4RANDOM
uint32_t arc4random(فراغ);
#جيڪڏهن_پورو /* !HAVE_ARC4RANDOM */

#جيڪڏهن_وصف_نه_ٿيل HAVE_ARC4RANDOM_BUF
فراغ arc4random_buf(فراغ *, سائيز_t);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_ARC4_RANDOM_هڪجهڙو
uint32_t arc4random_هڪجهڙو(uint32_t);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_ASPRINTF
صحيح asprintf(حرف **, ثابت حرف *, ...);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
صحيح openpty(صحيح *, صحيح *, حرف *, ثابت بنية termios *,
    ثابت بنية winsize *);
#جيڪڏهن_پورو /* HAVE_OPENPTY */

#جيڪڏهن_وصف_نه_ٿيل HAVE_SNPRINTF
صحيح snprintf(حرف *, سائيز_t, SNPRINTF_CONST حرف *, ...);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRTOLL
ڊگهو ڊگهو strtoll(ثابت حرف *, حرف **, صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRTOUL
بنانشان ڊگهو strtoul(ثابت حرف *, حرف **, صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRTOULL
بنانشان ڊگهو ڊگهو strtoull(ثابت حرف *, حرف **, صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRTONUM
ڊگهو ڊگهو strtonum(ثابت حرف *, ڊگهو ڊگهو, ڊگهو ڊگهو, ثابت حرف **);
#جيڪڏهن_پورو

/* multibyte character support */
#جيڪڏهن_وصف_نه_ٿيل HAVE_MBLEN
# define mblen(x, y)	(1)
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_WCWIDTH
# define wcwidth(x)	(((x) >= 0x20 && (x) <= 0x7e) ? 1 : -1)
/* force our no-op nl_langinfo and mbtowc */
# undef HAVE_NL_LANGINFO
# undef HAVE_MBTOWC
# undef HAVE_LANGINFO_H
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_NL_LANGINFO
# define nl_langinfo(x)	""
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_MBTOWC
صحيح mbtowc(wchar_t *, ثابت حرف*, سائيز_t);
#جيڪڏهن_پورو

#إذا !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
# include <stdarg.h>
#جيڪڏهن_پورو

/*
 * Some platforms unconditionally undefine va_copy() so we define VA_COPY()
 * instead.  This is known to be the case on at least some configurations of
 * AIX with the xlc compiler.
 */
#جيڪڏهن_وصف_نه_ٿيل VA_COPY
# ifdef HAVE_VA_COPY
#  define VA_COPY(dest, src) va_copy(dest, src)
# وإلا
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  وإلا
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_VASPRINTF
صحيح vasprintf(حرف **, ثابت حرف *, va_list);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_VSNPRINTF
صحيح vsnprintf(حرف *, سائيز_t, ثابت حرف *, va_list);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_USER_FROM_UID
حرف *user_from_uid(uid_t, صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_گروهه_FROM_GID
حرف *گروهه_from_gid(gid_t, صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_TIMINGSAFE_BCMP
صحيح timingsafe_bcmp(ثابت فراغ *, ثابت فراغ *, سائيز_t);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_BCRYPT_PBKDF
صحيح	bcrypt_pbkdf(ثابت حرف *, سائيز_t, ثابت uint8_t *, سائيز_t,
    uint8_t *, سائيز_t, بنانشان صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_EXPLICIT_BZERO
فراغ explicit_bzero(فراغ *p, سائيز_t n);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_FREEZERO
فراغ freezero(فراغ *, سائيز_t);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_LOCALTIME_R
بنية tm *localtime_r(ثابت time_t *, بنية tm *);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_TIMEGM
#ضمن <time.h>
time_t timegm(بنية tm *);
#جيڪڏهن_پورو

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
#إذا defined(HAVE_FEATURES_H) && defined(FORTIFY_ذريعو)
# include <features.h>
# إذا defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  إذا __GLIBC_PREREQ(2, 15) && (FORTIFY_ذريعو > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, سيٽ)	kludge_FD_سيٽ(n, سيٽ)
#   define FD_ISSET(n, سيٽ)	kludge_FD_ISSET(n, سيٽ)
فراغ kludge_FD_سيٽ(صحيح, fd_set *);
صحيح kludge_FD_ISSET(صحيح, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#جيڪڏهن_پورو /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#جيڪڏهن_پورو /* _OPENBSD_COMPAT_H */
