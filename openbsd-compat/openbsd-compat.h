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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <pwd.h>

#അന്തര്ഭാവ <sys/socket.h>

#അന്തര്ഭാവ <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#അന്തര്ഭാവ "base64.h"
#അന്തര്ഭാവ "sigact.h"
#അന്തര്ഭാവ "readpassphrase.h"
#അന്തര്ഭാവ "vis.h"
#അന്തര്ഭാവ "getrrsetbyname.h"
#അന്തര്ഭാവ "sha1.h"
#അന്തര്ഭാവ "bsd-sha2.h"
#അന്തര്ഭാവ "md5.h"
#അന്തര്ഭാവ "blf.h"
#അന്തര്ഭാവ "fnmatch.h"

#ifndef __THROW
# എങ്കിൽ defined __cplusplus
#  define __THROW throw()
# അല്ലെങ്കിൽ
#  define __THROW
# endif
#endif

#എങ്കിൽ defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#endif

#ifndef HAVE_BASENAME
അക്ഷരം *basename(സ്ഥിരം അക്ഷരം *path);
#endif

#ifndef HAVE_BINDRESVPORT_SA
പൂർണ്ണസംഖ്യ bindresvport_sa(പൂർണ്ണസംഖ്യ sd, ഘടന sockaddr *sa);
#endif

#ifndef HAVE_CLOSEFROM
ശൂന്യം closefrom(പൂർണ്ണസംഖ്യ);
#endif

#എങ്കിൽ defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
പൂർണ്ണസംഖ്യ ftruncate(പൂർണ്ണസംഖ്യ filedes, off_t length);
#endif

#ifndef HAVE_GETLINE
#അന്തര്ഭാവ <stdio.h>
ssize_t getline(അക്ഷരം **, size_t *, FILE *);
#endif

#ifndef HAVE_GETPAGESIZE
പൂർണ്ണസംഖ്യ getpagesize(ശൂന്യം);
#endif

#ifndef HAVE_GETCWD
അക്ഷരം *getcwd(അക്ഷരം *pt, size_t size);
#endif

#ifndef HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#define getexecpath(a, b) (-1)
#endif

#ifndef HAVE_KILLPG
പൂർണ്ണസംഖ്യ killpg(pid_t, പൂർണ്ണസംഖ്യ);
#endif

#എങ്കിൽ defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
ശൂന്യം *memmem(സ്ഥിരം ശൂന്യം *, size_t, സ്ഥിരം ശൂന്യം *, size_t);
#endif

#ifndef HAVE_REALLOCARRAY
ശൂന്യം *reallocarray(ശൂന്യം *, size_t, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
ശൂന്യം *recallocarray(ശൂന്യം *, size_t, size_t, size_t);
#endif

#ifndef HAVE_RRESVPORT_AF
പൂർണ്ണസംഖ്യ rresvport_af(പൂർണ്ണസംഖ്യ *alport, sa_family_t af);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(അക്ഷരം *dst, സ്ഥിരം അക്ഷരം *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(അക്ഷരം *dst, സ്ഥിരം അക്ഷരം *src, size_t siz);
#endif

#ifndef HAVE_STRCASESTR
അക്ഷരം *strcasestr(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(സ്ഥിരം അക്ഷരം *, size_t);
#endif

#ifndef HAVE_STRNDUP
അക്ഷരം *strndup(സ്ഥിരം അക്ഷരം *s, size_t n);
#endif

#ifndef HAVE_SETENV
പൂർണ്ണസംഖ്യ setenv(രജിസ്റ്റർ സ്ഥിരം അക്ഷരം *name, രജിസ്റ്റർ സ്ഥിരം അക്ഷരം *മൂല്യം, പൂർണ്ണസംഖ്യ rewrite);
#endif

#ifndef HAVE_STRMODE
ശൂന്യം strmode(പൂർണ്ണസംഖ്യ mode, അക്ഷരം *p);
#endif

#ifndef HAVE_STRPTIME
#അന്തര്ഭാവ  <time.h>
അക്ഷരം *strptime(സ്ഥിരം അക്ഷരം *buf, സ്ഥിരം അക്ഷരം *fmt, ഘടന tm *tm);
#endif

#എങ്കിൽ !defined(HAVE_MKDTEMP)
പൂർണ്ണസംഖ്യ mkstemps(അക്ഷരം *path, പൂർണ്ണസംഖ്യ slen);
പൂർണ്ണസംഖ്യ mkstemp(അക്ഷരം *path);
അക്ഷരം *mkdtemp(അക്ഷരം *path);
#endif

#define mkstemp(x) _ssh_mkstemp(x)
പൂർണ്ണസംഖ്യ _ssh_mkstemp(അക്ഷരം *);

#ifndef HAVE_DAEMON
പൂർണ്ണസംഖ്യ daemon(പൂർണ്ണസംഖ്യ nochdir, പൂർണ്ണസംഖ്യ noclose);
#endif

#ifndef HAVE_DIRNAME
അക്ഷരം *dirname(സ്ഥിരം അക്ഷരം *path);
#endif

#ifndef HAVE_FMT_SCALED
#define	FMT_SCALED_STRSIZE	7
പൂർണ്ണസംഖ്യ	fmt_scaled(long long സംഖ്യ, അക്ഷരം *result);
#endif

#ifndef HAVE_SCAN_SCALED
പൂർണ്ണസംഖ്യ	scan_scaled(അക്ഷരം *, long long *);
#endif

#എങ്കിൽ defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
അക്ഷരം *inet_ntoa(ഘടന in_addr in);
#endif

#ifndef HAVE_INET_NTOP
സ്ഥിരം അക്ഷരം *inet_ntop(പൂർണ്ണസംഖ്യ af, സ്ഥിരം ശൂന്യം *src, അക്ഷരം *dst, socklen_t size);
#endif

#ifndef HAVE_INET_ATON
പൂർണ്ണസംഖ്യ inet_aton(സ്ഥിരം അക്ഷരം *cp, ഘടന in_addr *addr);
#endif

#ifndef HAVE_STRSEP
അക്ഷരം *strsep(അക്ഷരം **stringp, സ്ഥിരം അക്ഷരം *delim);
#endif

#ifndef HAVE_SETPROCTITLE
ശൂന്യം setproctitle(സ്ഥിരം അക്ഷരം *fmt, ...);
ശൂന്യം compat_init_setproctitle(പൂർണ്ണസംഖ്യ argc, അക്ഷരം *argv[]);
#endif

#ifndef HAVE_GETGROUPLIST
പൂർണ്ണസംഖ്യ getgrouplist(സ്ഥിരം അക്ഷരം *, gid_t, gid_t *, പൂർണ്ണസംഖ്യ *);
#endif

#എങ്കിൽ !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
പൂർണ്ണസംഖ്യ BSDgetopt(പൂർണ്ണസംഖ്യ argc, അക്ഷരം * സ്ഥിരം *argv, സ്ഥിരം അക്ഷരം *opts) __THROW;
#അന്തര്ഭാവ "openbsd-compat/getopt.h"
#endif

#എങ്കിൽ ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# എങ്കിൽ defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
പൂർണ്ണസംഖ്യ readv(പൂർണ്ണസംഖ്യ, ഘടന iovec *, പൂർണ്ണസംഖ്യ);
# endif

# എങ്കിൽ defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
പൂർണ്ണസംഖ്യ writev(പൂർണ്ണസംഖ്യ, ഘടന iovec *, പൂർണ്ണസംഖ്യ);
# endif
#endif

/* Home grown routines */
#അന്തര്ഭാവ "bsd-signal.h"
#അന്തര്ഭാവ "bsd-misc.h"
#അന്തര്ഭാവ "bsd-setres_id.h"
#അന്തര്ഭാവ "bsd-statvfs.h"
#അന്തര്ഭാവ "bsd-waitpid.h"
#അന്തര്ഭാവ "bsd-poll.h"

#എങ്കിൽ defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
പൂർണ്ണസംഖ്യ getpeereid(പൂർണ്ണസംഖ്യ , uid_t *, gid_t *);
#endif

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(ശൂന്യം);
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_ARC4RANDOM_BUF
ശൂന്യം arc4random_buf(ശൂന്യം *, size_t);
#endif

#ifndef HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#endif

#ifndef HAVE_ASPRINTF
പൂർണ്ണസംഖ്യ asprintf(അക്ഷരം **, സ്ഥിരം അക്ഷരം *, ...);
#endif

#ifndef HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
പൂർണ്ണസംഖ്യ openpty(പൂർണ്ണസംഖ്യ *, പൂർണ്ണസംഖ്യ *, അക്ഷരം *, സ്ഥിരം ഘടന termios *,
    സ്ഥിരം ഘടന winsize *);
#endif /* HAVE_OPENPTY */

#ifndef HAVE_SNPRINTF
പൂർണ്ണസംഖ്യ snprintf(അക്ഷരം *, size_t, SNPRINTF_CONST അക്ഷരം *, ...);
#endif

#ifndef HAVE_STRTOLL
long long strtoll(സ്ഥിരം അക്ഷരം *, അക്ഷരം **, പൂർണ്ണസംഖ്യ);
#endif

#ifndef HAVE_STRTOUL
unsigned long strtoul(സ്ഥിരം അക്ഷരം *, അക്ഷരം **, പൂർണ്ണസംഖ്യ);
#endif

#ifndef HAVE_STRTOULL
unsigned long long strtoull(സ്ഥിരം അക്ഷരം *, അക്ഷരം **, പൂർണ്ണസംഖ്യ);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(സ്ഥിരം അക്ഷരം *, long long, long long, സ്ഥിരം അക്ഷരം **);
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
പൂർണ്ണസംഖ്യ mbtowc(wchar_t *, സ്ഥിരം അക്ഷരം*, size_t);
#endif

#എങ്കിൽ !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
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
# അല്ലെങ്കിൽ
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  അല്ലെങ്കിൽ
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#endif

#ifndef HAVE_VASPRINTF
പൂർണ്ണസംഖ്യ vasprintf(അക്ഷരം **, സ്ഥിരം അക്ഷരം *, va_list);
#endif

#ifndef HAVE_VSNPRINTF
പൂർണ്ണസംഖ്യ vsnprintf(അക്ഷരം *, size_t, സ്ഥിരം അക്ഷരം *, va_list);
#endif

#ifndef HAVE_USER_FROM_UID
അക്ഷരം *user_from_uid(uid_t, പൂർണ്ണസംഖ്യ);
#endif

#ifndef HAVE_GROUP_FROM_GID
അക്ഷരം *group_from_gid(gid_t, പൂർണ്ണസംഖ്യ);
#endif

#ifndef HAVE_TIMINGSAFE_BCMP
പൂർണ്ണസംഖ്യ timingsafe_bcmp(സ്ഥിരം ശൂന്യം *, സ്ഥിരം ശൂന്യം *, size_t);
#endif

#ifndef HAVE_BCRYPT_PBKDF
പൂർണ്ണസംഖ്യ	bcrypt_pbkdf(സ്ഥിരം അക്ഷരം *, size_t, സ്ഥിരം uint8_t *, size_t,
    uint8_t *, size_t, unsigned പൂർണ്ണസംഖ്യ);
#endif

#ifndef HAVE_EXPLICIT_BZERO
ശൂന്യം explicit_bzero(ശൂന്യം *p, size_t n);
#endif

#ifndef HAVE_FREEZERO
ശൂന്യം freezero(ശൂന്യം *, size_t);
#endif

#ifndef HAVE_LOCALTIME_R
ഘടന tm *localtime_r(സ്ഥിരം time_t *, ഘടന tm *);
#endif

#ifndef HAVE_TIMEGM
#അന്തര്ഭാവ <time.h>
time_t timegm(ഘടന tm *);
#endif

അക്ഷരം *xcrypt(സ്ഥിരം അക്ഷരം *password, സ്ഥിരം അക്ഷരം *salt);
അക്ഷരം *shadow_pw(ഘടന passwd *pw);

/* rfc2553 socket API replacements */
#അന്തര്ഭാവ "fake-rfc2553.h"

/* Routines for a single OS platform */
#അന്തര്ഭാവ "bsd-cygwin_util.h"

#അന്തര്ഭാവ "port-aix.h"
#അന്തര്ഭാവ "port-irix.h"
#അന്തര്ഭാവ "port-linux.h"
#അന്തര്ഭാവ "port-solaris.h"
#അന്തര്ഭാവ "port-net.h"
#അന്തര്ഭാവ "port-uw.h"

/* _FORTIFY_SOURCE breaks FD_ISSET(n)/FD_SET(n) for n > FD_SETSIZE. Avoid. */
#എങ്കിൽ defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# എങ്കിൽ defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  എങ്കിൽ __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, set)	kludge_FD_SET(n, set)
#   define FD_ISSET(n, set)	kludge_FD_ISSET(n, set)
ശൂന്യം kludge_FD_SET(പൂർണ്ണസംഖ്യ, fd_set *);
പൂർണ്ണസംഖ്യ kludge_FD_ISSET(പൂർണ്ണസംഖ്യ, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#endif /* _OPENBSD_COMPAT_H */
