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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _OPENBSD_COMPAT_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _OPENBSD_COMPAT_H

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#ਅਨ੍ਤਰ੍ਭਾਵ "base64.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sigact.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "readpassphrase.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "vis.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "getrrsetbyname.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sha1.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "bsd-sha2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "md5.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "blf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "fnmatch.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ __THROW
# ਜੇ defined __cplusplus
#  define __THROW throw()
# ਨਹੀਂਤਾਂ
#  define __THROW
# endif
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_BASENAME
ਅੱਖਰ *basename(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_BINDRESVPORT_SA
ਪੂਰਨ bindresvport_sa(ਪੂਰਨ sd, ਬਣਤਰ sockaddr *sa);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_CLOSEFROM
ਖਾਲੀ closefrom(ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
ਪੂਰਨ ftruncate(ਪੂਰਨ filedes, off_t ਲੰਮਾਈ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETLINE
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
ssize_t getline(ਅੱਖਰ **, ਮਾਪ_t *, FILE *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETPAGESIZE
ਪੂਰਨ getpagesize(ਖਾਲੀ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETCWD
ਅੱਖਰ *getcwd(ਅੱਖਰ *pt, ਮਾਪ_t ਮਾਪ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ getexecpath(a, b) (-1)
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_KILLPG
ਪੂਰਨ killpg(pid_t, ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
ਖਾਲੀ *memmem(ਅਚਲ ਖਾਲੀ *, ਮਾਪ_t, ਅਚਲ ਖਾਲੀ *, ਮਾਪ_t);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_REALLOCARRAY
ਖਾਲੀ *reallocarray(ਖਾਲੀ *, ਮਾਪ_t, ਮਾਪ_t);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_RECALLOCARRAY
ਖਾਲੀ *recallocarray(ਖਾਲੀ *, ਮਾਪ_t, ਮਾਪ_t, ਮਾਪ_t);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_RRESVPORT_AF
ਪੂਰਨ rresvport_af(ਪੂਰਨ *alport, sa_family_t af);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRLCPY
ਮਾਪ_t strlcpy(ਅੱਖਰ *dst, ਅਚਲ ਅੱਖਰ *src, ਮਾਪ_t siz);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRLCAT
ਮਾਪ_t strlcat(ਅੱਖਰ *dst, ਅਚਲ ਅੱਖਰ *src, ਮਾਪ_t siz);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRCASESTR
ਅੱਖਰ *strcasestr(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRNLEN
ਮਾਪ_t strnlen(ਅਚਲ ਅੱਖਰ *, ਮਾਪ_t);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRNDUP
ਅੱਖਰ *strndup(ਅਚਲ ਅੱਖਰ *s, ਮਾਪ_t n);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SETENV
ਪੂਰਨ setenv(ਰਜਿਸਟਰ ਅਚਲ ਅੱਖਰ *name, ਰਜਿਸਟਰ ਅਚਲ ਅੱਖਰ *ਮੁੱਲ, ਪੂਰਨ rewrite);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRMODE
ਖਾਲੀ strmode(ਪੂਰਨ ਬਹੁਲਕ, ਅੱਖਰ *p);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRPTIME
#ਅਨ੍ਤਰ੍ਭਾਵ  <time.h>
ਅੱਖਰ *strptime(ਅਚਲ ਅੱਖਰ *buf, ਅਚਲ ਅੱਖਰ *fmt, ਬਣਤਰ tm *tm);
#ਜੇ_ਅੰਤ

#ਜੇ !defined(HAVE_MKDTEMP)
ਪੂਰਨ mkstemps(ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ slen);
ਪੂਰਨ mkstemp(ਅੱਖਰ *ਰਸਤਾ);
ਅੱਖਰ *mkdtemp(ਅੱਖਰ *ਰਸਤਾ);
#ਜੇ_ਅੰਤ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ mkstemp(x) _ssh_mkstemp(x)
ਪੂਰਨ _ssh_mkstemp(ਅੱਖਰ *);

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_DAEMON
ਪੂਰਨ daemon(ਪੂਰਨ nochdir, ਪੂਰਨ noclose);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_DIRNAME
ਅੱਖਰ *dirname(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FMT_SCALED
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	FMT_SCALED_STRSIZE	7
ਪੂਰਨ	fmt_scaled(ਲੰਮਾ ਲੰਮਾ ਸੰਖਿਆ, ਅੱਖਰ *ਨਤੀਜਾ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ਜਾਂਚ_SCALED
ਪੂਰਨ	ਜਾਂਚ_scaled(ਅੱਖਰ *, ਲੰਮਾ ਲੰਮਾ *);
#ਜੇ_ਅੰਤ

#ਜੇ defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
ਅੱਖਰ *inet_ntoa(ਬਣਤਰ in_addr ਵਿੱਚ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_INET_NTOP
ਅਚਲ ਅੱਖਰ *inet_ntop(ਪੂਰਨ af, ਅਚਲ ਖਾਲੀ *src, ਅੱਖਰ *dst, socklen_t ਮਾਪ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_INET_ATON
ਪੂਰਨ inet_aton(ਅਚਲ ਅੱਖਰ *cp, ਬਣਤਰ in_addr *addr);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRSEP
ਅੱਖਰ *strsep(ਅੱਖਰ **stringp, ਅਚਲ ਅੱਖਰ *delim);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SETPROCTITLE
ਖਾਲੀ setproctitle(ਅਚਲ ਅੱਖਰ *fmt, ...);
ਖਾਲੀ compat_init_setproctitle(ਪੂਰਨ argc, ਅੱਖਰ *argv[]);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETGROUPLIST
ਪੂਰਨ getgrouplist(ਅਚਲ ਅੱਖਰ *, gid_t, gid_t *, ਪੂਰਨ *);
#ਜੇ_ਅੰਤ

#ਜੇ !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
ਪੂਰਨ BSDgetopt(ਪੂਰਨ argc, ਅੱਖਰ * ਅਚਲ *argv, ਅਚਲ ਅੱਖਰ *opts) __THROW;
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/getopt.h"
#ਜੇ_ਅੰਤ

#ਜੇ ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# ਜੇ defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
ਪੂਰਨ readv(ਪੂਰਨ, ਬਣਤਰ iovec *, ਪੂਰਨ);
# endif

# ਜੇ defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
ਪੂਰਨ writev(ਪੂਰਨ, ਬਣਤਰ iovec *, ਪੂਰਨ);
# endif
#ਜੇ_ਅੰਤ

/* Home grown routines */
#ਅਨ੍ਤਰ੍ਭਾਵ "bsd-signal.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "bsd-misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "bsd-setres_id.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "bsd-statvfs.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "bsd-waitpid.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "bsd-poll.h"

#ਜੇ defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
ਪੂਰਨ getpeereid(ਪੂਰਨ , uid_t *, gid_t *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ARC4RANDOM
uint32_t arc4random(ਖਾਲੀ);
#ਜੇ_ਅੰਤ /* !HAVE_ARC4RANDOM */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ARC4RANDOM_BUF
ਖਾਲੀ arc4random_buf(ਖਾਲੀ *, ਮਾਪ_t);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ARC4_RANDOM_ਇਕਸਾਰ
uint32_t arc4random_ਇਕਸਾਰ(uint32_t);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ASPRINTF
ਪੂਰਨ asprintf(ਅੱਖਰ **, ਅਚਲ ਅੱਖਰ *, ...);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
ਪੂਰਨ openpty(ਪੂਰਨ *, ਪੂਰਨ *, ਅੱਖਰ *, ਅਚਲ ਬਣਤਰ termios *,
    ਅਚਲ ਬਣਤਰ winsize *);
#ਜੇ_ਅੰਤ /* HAVE_OPENPTY */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SNPRINTF
ਪੂਰਨ snprintf(ਅੱਖਰ *, ਮਾਪ_t, SNPRINTF_CONST ਅੱਖਰ *, ...);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRTOLL
ਲੰਮਾ ਲੰਮਾ strtoll(ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ **, ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRTOUL
ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ strtoul(ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ **, ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRTOULL
ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ strtoull(ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ **, ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRTONUM
ਲੰਮਾ ਲੰਮਾ strtonum(ਅਚਲ ਅੱਖਰ *, ਲੰਮਾ ਲੰਮਾ, ਲੰਮਾ ਲੰਮਾ, ਅਚਲ ਅੱਖਰ **);
#ਜੇ_ਅੰਤ

/* multibyte character support */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_MBLEN
# define mblen(x, y)	(1)
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_WCWIDTH
# define wcwidth(x)	(((x) >= 0x20 && (x) <= 0x7e) ? 1 : -1)
/* force our no-op nl_langinfo and mbtowc */
# undef HAVE_NL_LANGINFO
# undef HAVE_MBTOWC
# undef HAVE_LANGINFO_H
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_NL_LANGINFO
# define nl_langinfo(x)	""
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_MBTOWC
ਪੂਰਨ mbtowc(wchar_t *, ਅਚਲ ਅੱਖਰ*, ਮਾਪ_t);
#ਜੇ_ਅੰਤ

#ਜੇ !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
# include <stdarg.h>
#ਜੇ_ਅੰਤ

/*
 * Some platforms unconditionally undefine va_copy() so we define VA_COPY()
 * instead.  This is known to be the case on at least some configurations of
 * AIX with the xlc compiler.
 */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ VA_COPY
# ifdef HAVE_VA_COPY
#  define VA_COPY(dest, src) va_copy(dest, src)
# ਨਹੀਂਤਾਂ
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  ਨਹੀਂਤਾਂ
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_VASPRINTF
ਪੂਰਨ vasprintf(ਅੱਖਰ **, ਅਚਲ ਅੱਖਰ *, va_list);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_VSNPRINTF
ਪੂਰਨ vsnprintf(ਅੱਖਰ *, ਮਾਪ_t, ਅਚਲ ਅੱਖਰ *, va_list);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_USER_FROM_UID
ਅੱਖਰ *user_from_uid(uid_t, ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ਸਮੂਹ_FROM_GID
ਅੱਖਰ *ਸਮੂਹ_from_gid(gid_t, ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_TIMINGSAFE_BCMP
ਪੂਰਨ timingsafe_bcmp(ਅਚਲ ਖਾਲੀ *, ਅਚਲ ਖਾਲੀ *, ਮਾਪ_t);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_BCRYPT_PBKDF
ਪੂਰਨ	bcrypt_pbkdf(ਅਚਲ ਅੱਖਰ *, ਮਾਪ_t, ਅਚਲ uint8_t *, ਮਾਪ_t,
    uint8_t *, ਮਾਪ_t, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_EXPLICIT_BZERO
ਖਾਲੀ explicit_bzero(ਖਾਲੀ *p, ਮਾਪ_t n);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FREEZERO
ਖਾਲੀ freezero(ਖਾਲੀ *, ਮਾਪ_t);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_LOCALTIME_R
ਬਣਤਰ tm *localtime_r(ਅਚਲ time_t *, ਬਣਤਰ tm *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_TIMEGM
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
time_t timegm(ਬਣਤਰ tm *);
#ਜੇ_ਅੰਤ

ਅੱਖਰ *xcrypt(ਅਚਲ ਅੱਖਰ *password, ਅਚਲ ਅੱਖਰ *salt);
ਅੱਖਰ *shadow_pw(ਬਣਤਰ passwd *pw);

/* rfc2553 socket API replacements */
#ਅਨ੍ਤਰ੍ਭਾਵ "fake-rfc2553.h"

/* Routines for a single OS platform */
#ਅਨ੍ਤਰ੍ਭਾਵ "bsd-cygwin_util.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "port-aix.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "port-irix.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "port-linux.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "port-solaris.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "port-net.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "port-uw.h"

/* _FORTIFY_SOURCE breaks FD_ISSET(n)/FD_SET(n) for n > FD_SETSIZE. Avoid. */
#ਜੇ defined(HAVE_FEATURES_H) && defined(FORTIFY_ਸਰੋਤ)
# include <features.h>
# ਜੇ defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  ਜੇ __GLIBC_PREREQ(2, 15) && (FORTIFY_ਸਰੋਤ > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, ਸੈੱਟ)	kludge_FD_ਸੈੱਟ(n, ਸੈੱਟ)
#   define FD_ISSET(n, ਸੈੱਟ)	kludge_FD_ISSET(n, ਸੈੱਟ)
ਖਾਲੀ kludge_FD_ਸੈੱਟ(ਪੂਰਨ, fd_set *);
ਪੂਰਨ kludge_FD_ISSET(ਪੂਰਨ, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#ਜੇ_ਅੰਤ /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#ਜੇ_ਅੰਤ /* _OPENBSD_COMPAT_H */
