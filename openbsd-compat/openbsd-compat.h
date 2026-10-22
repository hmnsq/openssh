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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <pwd.h>

#અન્તર્ભાવ <sys/socket.h>

#અન્તર્ભાવ <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#અન્તર્ભાવ "base64.h"
#અન્તર્ભાવ "sigact.h"
#અન્તર્ભાવ "readpassphrase.h"
#અન્તર્ભાવ "vis.h"
#અન્તર્ભાવ "getrrsetbyname.h"
#અન્તર્ભાવ "sha1.h"
#અન્તર્ભાવ "bsd-sha2.h"
#અન્તર્ભાવ "md5.h"
#અન્તર્ભાવ "blf.h"
#અન્તર્ભાવ "fnmatch.h"

#ifndef __THROW
# જો defined __cplusplus
#  define __THROW throw()
# નહીંતર
#  define __THROW
# endif
#endif

#જો defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#endif

#ifndef HAVE_BASENAME
અક્ષર *basename(અચલ અક્ષર *path);
#endif

#ifndef HAVE_BINDRESVPORT_SA
પૂર્ણાંક bindresvport_sa(પૂર્ણાંક sd, સંરચના sockaddr *sa);
#endif

#ifndef HAVE_CLOSEFROM
શૂન્ય closefrom(પૂર્ણાંક);
#endif

#જો defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
પૂર્ણાંક ftruncate(પૂર્ણાંક filedes, off_t length);
#endif

#ifndef HAVE_GETLINE
#અન્તર્ભાવ <stdio.h>
ssize_t getline(અક્ષર **, size_t *, FILE *);
#endif

#ifndef HAVE_GETPAGESIZE
પૂર્ણાંક getpagesize(શૂન્ય);
#endif

#ifndef HAVE_GETCWD
અક્ષર *getcwd(અક્ષર *pt, size_t size);
#endif

#ifndef HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#define getexecpath(a, b) (-1)
#endif

#ifndef HAVE_KILLPG
પૂર્ણાંક killpg(pid_t, પૂર્ણાંક);
#endif

#જો defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
શૂન્ય *memmem(અચલ શૂન્ય *, size_t, અચલ શૂન્ય *, size_t);
#endif

#ifndef HAVE_REALLOCARRAY
શૂન્ય *reallocarray(શૂન્ય *, size_t, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
શૂન્ય *recallocarray(શૂન્ય *, size_t, size_t, size_t);
#endif

#ifndef HAVE_RRESVPORT_AF
પૂર્ણાંક rresvport_af(પૂર્ણાંક *alport, sa_family_t af);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(અક્ષર *dst, અચલ અક્ષર *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(અક્ષર *dst, અચલ અક્ષર *src, size_t siz);
#endif

#ifndef HAVE_STRCASESTR
અક્ષર *strcasestr(અચલ અક્ષર *, અચલ અક્ષર *);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(અચલ અક્ષર *, size_t);
#endif

#ifndef HAVE_STRNDUP
અક્ષર *strndup(અચલ અક્ષર *s, size_t n);
#endif

#ifndef HAVE_SETENV
પૂર્ણાંક setenv(નોંધણી અચલ અક્ષર *name, નોંધણી અચલ અક્ષર *કિંમત, પૂર્ણાંક rewrite);
#endif

#ifndef HAVE_STRMODE
શૂન્ય strmode(પૂર્ણાંક mode, અક્ષર *p);
#endif

#ifndef HAVE_STRPTIME
#અન્તર્ભાવ  <time.h>
અક્ષર *strptime(અચલ અક્ષર *buf, અચલ અક્ષર *fmt, સંરચના tm *tm);
#endif

#જો !defined(HAVE_MKDTEMP)
પૂર્ણાંક mkstemps(અક્ષર *path, પૂર્ણાંક slen);
પૂર્ણાંક mkstemp(અક્ષર *path);
અક્ષર *mkdtemp(અક્ષર *path);
#endif

#define mkstemp(x) _ssh_mkstemp(x)
પૂર્ણાંક _ssh_mkstemp(અક્ષર *);

#ifndef HAVE_DAEMON
પૂર્ણાંક daemon(પૂર્ણાંક nochdir, પૂર્ણાંક noclose);
#endif

#ifndef HAVE_DIRNAME
અક્ષર *dirname(અચલ અક્ષર *path);
#endif

#ifndef HAVE_FMT_SCALED
#define	FMT_SCALED_STRSIZE	7
પૂર્ણાંક	fmt_scaled(long long સંખ્યા, અક્ષર *result);
#endif

#ifndef HAVE_SCAN_SCALED
પૂર્ણાંક	scan_scaled(અક્ષર *, long long *);
#endif

#જો defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
અક્ષર *inet_ntoa(સંરચના in_addr in);
#endif

#ifndef HAVE_INET_NTOP
અચલ અક્ષર *inet_ntop(પૂર્ણાંક af, અચલ શૂન્ય *src, અક્ષર *dst, socklen_t size);
#endif

#ifndef HAVE_INET_ATON
પૂર્ણાંક inet_aton(અચલ અક્ષર *cp, સંરચના in_addr *addr);
#endif

#ifndef HAVE_STRSEP
અક્ષર *strsep(અક્ષર **stringp, અચલ અક્ષર *delim);
#endif

#ifndef HAVE_SETPROCTITLE
શૂન્ય setproctitle(અચલ અક્ષર *fmt, ...);
શૂન્ય compat_init_setproctitle(પૂર્ણાંક argc, અક્ષર *argv[]);
#endif

#ifndef HAVE_GETGROUPLIST
પૂર્ણાંક getgrouplist(અચલ અક્ષર *, gid_t, gid_t *, પૂર્ણાંક *);
#endif

#જો !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
પૂર્ણાંક BSDgetopt(પૂર્ણાંક argc, અક્ષર * અચલ *argv, અચલ અક્ષર *opts) __THROW;
#અન્તર્ભાવ "openbsd-compat/getopt.h"
#endif

#જો ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# જો defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
પૂર્ણાંક readv(પૂર્ણાંક, સંરચના iovec *, પૂર્ણાંક);
# endif

# જો defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
પૂર્ણાંક writev(પૂર્ણાંક, સંરચના iovec *, પૂર્ણાંક);
# endif
#endif

/* Home grown routines */
#અન્તર્ભાવ "bsd-signal.h"
#અન્તર્ભાવ "bsd-misc.h"
#અન્તર્ભાવ "bsd-setres_id.h"
#અન્તર્ભાવ "bsd-statvfs.h"
#અન્તર્ભાવ "bsd-waitpid.h"
#અન્તર્ભાવ "bsd-poll.h"

#જો defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
પૂર્ણાંક getpeereid(પૂર્ણાંક , uid_t *, gid_t *);
#endif

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(શૂન્ય);
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_ARC4RANDOM_BUF
શૂન્ય arc4random_buf(શૂન્ય *, size_t);
#endif

#ifndef HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#endif

#ifndef HAVE_ASPRINTF
પૂર્ણાંક asprintf(અક્ષર **, અચલ અક્ષર *, ...);
#endif

#ifndef HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
પૂર્ણાંક openpty(પૂર્ણાંક *, પૂર્ણાંક *, અક્ષર *, અચલ સંરચના termios *,
    અચલ સંરચના winsize *);
#endif /* HAVE_OPENPTY */

#ifndef HAVE_SNPRINTF
પૂર્ણાંક snprintf(અક્ષર *, size_t, SNPRINTF_CONST અક્ષર *, ...);
#endif

#ifndef HAVE_STRTOLL
long long strtoll(અચલ અક્ષર *, અક્ષર **, પૂર્ણાંક);
#endif

#ifndef HAVE_STRTOUL
unsigned long strtoul(અચલ અક્ષર *, અક્ષર **, પૂર્ણાંક);
#endif

#ifndef HAVE_STRTOULL
unsigned long long strtoull(અચલ અક્ષર *, અક્ષર **, પૂર્ણાંક);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(અચલ અક્ષર *, long long, long long, અચલ અક્ષર **);
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
પૂર્ણાંક mbtowc(wchar_t *, અચલ અક્ષર*, size_t);
#endif

#જો !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
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
# નહીંતર
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  નહીંતર
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#endif

#ifndef HAVE_VASPRINTF
પૂર્ણાંક vasprintf(અક્ષર **, અચલ અક્ષર *, va_list);
#endif

#ifndef HAVE_VSNPRINTF
પૂર્ણાંક vsnprintf(અક્ષર *, size_t, અચલ અક્ષર *, va_list);
#endif

#ifndef HAVE_USER_FROM_UID
અક્ષર *user_from_uid(uid_t, પૂર્ણાંક);
#endif

#ifndef HAVE_GROUP_FROM_GID
અક્ષર *group_from_gid(gid_t, પૂર્ણાંક);
#endif

#ifndef HAVE_TIMINGSAFE_BCMP
પૂર્ણાંક timingsafe_bcmp(અચલ શૂન્ય *, અચલ શૂન્ય *, size_t);
#endif

#ifndef HAVE_BCRYPT_PBKDF
પૂર્ણાંક	bcrypt_pbkdf(અચલ અક્ષર *, size_t, અચલ uint8_t *, size_t,
    uint8_t *, size_t, unsigned પૂર્ણાંક);
#endif

#ifndef HAVE_EXPLICIT_BZERO
શૂન્ય explicit_bzero(શૂન્ય *p, size_t n);
#endif

#ifndef HAVE_FREEZERO
શૂન્ય freezero(શૂન્ય *, size_t);
#endif

#ifndef HAVE_LOCALTIME_R
સંરચના tm *localtime_r(અચલ time_t *, સંરચના tm *);
#endif

#ifndef HAVE_TIMEGM
#અન્તર્ભાવ <time.h>
time_t timegm(સંરચના tm *);
#endif

અક્ષર *xcrypt(અચલ અક્ષર *password, અચલ અક્ષર *salt);
અક્ષર *shadow_pw(સંરચના passwd *pw);

/* rfc2553 socket API replacements */
#અન્તર્ભાવ "fake-rfc2553.h"

/* Routines for a single OS platform */
#અન્તર્ભાવ "bsd-cygwin_util.h"

#અન્તર્ભાવ "port-aix.h"
#અન્તર્ભાવ "port-irix.h"
#અન્તર્ભાવ "port-linux.h"
#અન્તર્ભાવ "port-solaris.h"
#અન્તર્ભાવ "port-net.h"
#અન્તર્ભાવ "port-uw.h"

/* _FORTIFY_SOURCE breaks FD_ISSET(n)/FD_SET(n) for n > FD_SETSIZE. Avoid. */
#જો defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# જો defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  જો __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, set)	kludge_FD_SET(n, set)
#   define FD_ISSET(n, set)	kludge_FD_ISSET(n, set)
શૂન્ય kludge_FD_SET(પૂર્ણાંક, fd_set *);
પૂર્ણાંક kludge_FD_ISSET(પૂર્ણાંક, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#endif /* _OPENBSD_COMPAT_H */
