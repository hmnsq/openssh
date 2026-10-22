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

#اگر_غیر_تعریف_شدہ _OPENBSD_COMPAT_H
#تعریف_کرو _OPENBSD_COMPAT_H

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <pwd.h>

#شامل <sys/socket.h>

#شامل <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#شامل "base64.h"
#شامل "sigact.h"
#شامل "readpassphrase.h"
#شامل "vis.h"
#شامل "getrrsetbyname.h"
#شامل "sha1.h"
#شامل "bsd-sha2.h"
#شامل "md5.h"
#شامل "blf.h"
#شامل "fnmatch.h"

#اگر_غیر_تعریف_شدہ __THROW
# اگر defined __cplusplus
#  define __THROW throw()
# ورنہ
#  define __THROW
# endif
#اگر_ختم

#اگر defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_BASENAME
حرف *basename(ثابت حرف *راستہ);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_BINDRESVPORT_SA
صحیح bindresvport_sa(صحیح sd, ساخت sockaddr *sa);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_CLOSEFROM
خالی closefrom(صحیح);
#اگر_ختم

#اگر defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
صحیح ftruncate(صحیح filedes, off_t لمبائی);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_GETLINE
#شامل <stdio.h>
ssize_t getline(حرف **, سائز_t *, FILE *);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_GETPAGESIZE
صحیح getpagesize(خالی);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_GETCWD
حرف *getcwd(حرف *pt, سائز_t سائز);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#تعریف_کرو getexecpath(a, b) (-1)
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_KILLPG
صحیح killpg(pid_t, صحیح);
#اگر_ختم

#اگر defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
خالی *memmem(ثابت خالی *, سائز_t, ثابت خالی *, سائز_t);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_REALLOCARRAY
خالی *reallocarray(خالی *, سائز_t, سائز_t);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_RECALLOCARRAY
خالی *recallocarray(خالی *, سائز_t, سائز_t, سائز_t);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_RRESVPORT_AF
صحیح rresvport_af(صحیح *alport, sa_family_t af);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_STRLCPY
سائز_t strlcpy(حرف *dst, ثابت حرف *src, سائز_t siz);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_STRLCAT
سائز_t strlcat(حرف *dst, ثابت حرف *src, سائز_t siz);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_STRCASESTR
حرف *strcasestr(ثابت حرف *, ثابت حرف *);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_STRNLEN
سائز_t strnlen(ثابت حرف *, سائز_t);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_STRNDUP
حرف *strndup(ثابت حرف *s, سائز_t n);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_SETENV
صحیح setenv(اندراج ثابت حرف *name, اندراج ثابت حرف *قدر, صحیح rewrite);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_STRMODE
خالی strmode(صحیح منوال, حرف *p);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_STRPTIME
#شامل  <time.h>
حرف *strptime(ثابت حرف *buf, ثابت حرف *fmt, ساخت tm *tm);
#اگر_ختم

#اگر !defined(HAVE_MKDTEMP)
صحیح mkstemps(حرف *راستہ, صحیح slen);
صحیح mkstemp(حرف *راستہ);
حرف *mkdtemp(حرف *راستہ);
#اگر_ختم

#تعریف_کرو mkstemp(x) _ssh_mkstemp(x)
صحیح _ssh_mkstemp(حرف *);

#اگر_غیر_تعریف_شدہ HAVE_DAEMON
صحیح daemon(صحیح nochdir, صحیح noclose);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_DIRNAME
حرف *dirname(ثابت حرف *راستہ);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_FMT_SCALED
#تعریف_کرو	FMT_SCALED_STRSIZE	7
صحیح	fmt_scaled(طویل طویل نمبر, حرف *نتیجہ);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_جائزہ_SCALED
صحیح	جائزہ_scaled(حرف *, طویل طویل *);
#اگر_ختم

#اگر defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
حرف *inet_ntoa(ساخت in_addr اندر);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_INET_NTOP
ثابت حرف *inet_ntop(صحیح af, ثابت خالی *src, حرف *dst, socklen_t سائز);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_INET_ATON
صحیح inet_aton(ثابت حرف *cp, ساخت in_addr *addr);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_STRSEP
حرف *strsep(حرف **stringp, ثابت حرف *delim);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_SETPROCTITLE
خالی setproctitle(ثابت حرف *fmt, ...);
خالی compat_init_setproctitle(صحیح argc, حرف *argv[]);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_GETGROUPLIST
صحیح getgrouplist(ثابت حرف *, gid_t, gid_t *, صحیح *);
#اگر_ختم

#اگر !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
صحیح BSDgetopt(صحیح argc, حرف * ثابت *argv, ثابت حرف *opts) __THROW;
#شامل "openbsd-compat/getopt.h"
#اگر_ختم

#اگر ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# اگر defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
صحیح readv(صحیح, ساخت iovec *, صحیح);
# endif

# اگر defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
صحیح writev(صحیح, ساخت iovec *, صحیح);
# endif
#اگر_ختم

/* Home grown routines */
#شامل "bsd-signal.h"
#شامل "bsd-misc.h"
#شامل "bsd-setres_id.h"
#شامل "bsd-statvfs.h"
#شامل "bsd-waitpid.h"
#شامل "bsd-poll.h"

#اگر defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
صحیح getpeereid(صحیح , uid_t *, gid_t *);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_ARC4RANDOM
uint32_t arc4random(خالی);
#اگر_ختم /* !HAVE_ARC4RANDOM */

#اگر_غیر_تعریف_شدہ HAVE_ARC4RANDOM_BUF
خالی arc4random_buf(خالی *, سائز_t);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_ARC4_RANDOM_یکساں
uint32_t arc4random_یکساں(uint32_t);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_ASPRINTF
صحیح asprintf(حرف **, ثابت حرف *, ...);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
صحیح openpty(صحیح *, صحیح *, حرف *, ثابت ساخت termios *,
    ثابت ساخت winsize *);
#اگر_ختم /* HAVE_OPENPTY */

#اگر_غیر_تعریف_شدہ HAVE_SNPRINTF
صحیح snprintf(حرف *, سائز_t, SNPRINTF_CONST حرف *, ...);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_STRTOLL
طویل طویل strtoll(ثابت حرف *, حرف **, صحیح);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_STRTOUL
غیرعلامتی طویل strtoul(ثابت حرف *, حرف **, صحیح);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_STRTOULL
غیرعلامتی طویل طویل strtoull(ثابت حرف *, حرف **, صحیح);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_STRTONUM
طویل طویل strtonum(ثابت حرف *, طویل طویل, طویل طویل, ثابت حرف **);
#اگر_ختم

/* multibyte character support */
#اگر_غیر_تعریف_شدہ HAVE_MBLEN
# define mblen(x, y)	(1)
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_WCWIDTH
# define wcwidth(x)	(((x) >= 0x20 && (x) <= 0x7e) ? 1 : -1)
/* force our no-op nl_langinfo and mbtowc */
# undef HAVE_NL_LANGINFO
# undef HAVE_MBTOWC
# undef HAVE_LANGINFO_H
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_NL_LANGINFO
# define nl_langinfo(x)	""
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_MBTOWC
صحیح mbtowc(wchar_t *, ثابت حرف*, سائز_t);
#اگر_ختم

#اگر !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
# include <stdarg.h>
#اگر_ختم

/*
 * Some platforms unconditionally undefine va_copy() so we define VA_COPY()
 * instead.  This is known to be the case on at least some configurations of
 * AIX with the xlc compiler.
 */
#اگر_غیر_تعریف_شدہ VA_COPY
# ifdef HAVE_VA_COPY
#  define VA_COPY(dest, src) va_copy(dest, src)
# ورنہ
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  ورنہ
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_VASPRINTF
صحیح vasprintf(حرف **, ثابت حرف *, va_list);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_VSNPRINTF
صحیح vsnprintf(حرف *, سائز_t, ثابت حرف *, va_list);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_USER_FROM_UID
حرف *user_from_uid(uid_t, صحیح);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_گروہ_FROM_GID
حرف *گروہ_from_gid(gid_t, صحیح);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_TIMINGSAFE_BCMP
صحیح timingsafe_bcmp(ثابت خالی *, ثابت خالی *, سائز_t);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_BCRYPT_PBKDF
صحیح	bcrypt_pbkdf(ثابت حرف *, سائز_t, ثابت uint8_t *, سائز_t,
    uint8_t *, سائز_t, غیرعلامتی صحیح);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_EXPLICIT_BZERO
خالی explicit_bzero(خالی *p, سائز_t n);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_FREEZERO
خالی freezero(خالی *, سائز_t);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_LOCALTIME_R
ساخت tm *localtime_r(ثابت time_t *, ساخت tm *);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_TIMEGM
#شامل <time.h>
time_t timegm(ساخت tm *);
#اگر_ختم

حرف *xcrypt(ثابت حرف *password, ثابت حرف *salt);
حرف *shadow_pw(ساخت passwd *pw);

/* rfc2553 socket API replacements */
#شامل "fake-rfc2553.h"

/* Routines for a single OS platform */
#شامل "bsd-cygwin_util.h"

#شامل "port-aix.h"
#شامل "port-irix.h"
#شامل "port-linux.h"
#شامل "port-solaris.h"
#شامل "port-net.h"
#شامل "port-uw.h"

/* _FORTIFY_SOURCE breaks FD_ISSET(n)/FD_SET(n) for n > FD_SETSIZE. Avoid. */
#اگر defined(HAVE_FEATURES_H) && defined(FORTIFY_ماخذ)
# include <features.h>
# اگر defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  اگر __GLIBC_PREREQ(2, 15) && (FORTIFY_ماخذ > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, سیٹ)	kludge_FD_سیٹ(n, سیٹ)
#   define FD_ISSET(n, سیٹ)	kludge_FD_ISSET(n, سیٹ)
خالی kludge_FD_سیٹ(صحیح, fd_set *);
صحیح kludge_FD_ISSET(صحیح, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#اگر_ختم /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#اگر_ختم /* _OPENBSD_COMPAT_H */
