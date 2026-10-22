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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <pwd.h>

#अन्तर्भाव <sys/socket.h>

#अन्तर्भाव <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#अन्तर्भाव "base64.h"
#अन्तर्भाव "sigact.h"
#अन्तर्भाव "readpassphrase.h"
#अन्तर्भाव "vis.h"
#अन्तर्भाव "getrrsetbyname.h"
#अन्तर्भाव "sha1.h"
#अन्तर्भाव "bsd-sha2.h"
#अन्तर्भाव "md5.h"
#अन्तर्भाव "blf.h"
#अन्तर्भाव "fnmatch.h"

#ifndef __THROW
# सचे defined __cplusplus
#  define __THROW throw()
# अञ्ञथा
#  define __THROW
# endif
#endif

#सचे defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#endif

#ifndef HAVE_BASENAME
वर्ण *basename(ध्रुव वर्ण *path);
#endif

#ifndef HAVE_BINDRESVPORT_SA
पूर्णाङ्क bindresvport_sa(पूर्णाङ्क sd, संरचना sockaddr *sa);
#endif

#ifndef HAVE_CLOSEFROM
शून्य closefrom(पूर्णाङ्क);
#endif

#सचे defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
पूर्णाङ्क ftruncate(पूर्णाङ्क filedes, off_t length);
#endif

#ifndef HAVE_GETLINE
#अन्तर्भाव <stdio.h>
ssize_t getline(वर्ण **, size_t *, FILE *);
#endif

#ifndef HAVE_GETPAGESIZE
पूर्णाङ्क getpagesize(शून्य);
#endif

#ifndef HAVE_GETCWD
वर्ण *getcwd(वर्ण *pt, size_t size);
#endif

#ifndef HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#define getexecpath(a, b) (-1)
#endif

#ifndef HAVE_KILLPG
पूर्णाङ्क killpg(pid_t, पूर्णाङ्क);
#endif

#सचे defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
शून्य *memmem(ध्रुव शून्य *, size_t, ध्रुव शून्य *, size_t);
#endif

#ifndef HAVE_REALLOCARRAY
शून्य *reallocarray(शून्य *, size_t, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
शून्य *recallocarray(शून्य *, size_t, size_t, size_t);
#endif

#ifndef HAVE_RRESVPORT_AF
पूर्णाङ्क rresvport_af(पूर्णाङ्क *alport, sa_family_t af);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(वर्ण *dst, ध्रुव वर्ण *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(वर्ण *dst, ध्रुव वर्ण *src, size_t siz);
#endif

#ifndef HAVE_STRCASESTR
वर्ण *strcasestr(ध्रुव वर्ण *, ध्रुव वर्ण *);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(ध्रुव वर्ण *, size_t);
#endif

#ifndef HAVE_STRNDUP
वर्ण *strndup(ध्रुव वर्ण *s, size_t n);
#endif

#ifndef HAVE_SETENV
पूर्णाङ्क setenv(पञ्जिका ध्रुव वर्ण *name, पञ्जिका ध्रुव वर्ण *मानम्, पूर्णाङ्क rewrite);
#endif

#ifndef HAVE_STRMODE
शून्य strmode(पूर्णाङ्क mode, वर्ण *p);
#endif

#ifndef HAVE_STRPTIME
#अन्तर्भाव  <time.h>
वर्ण *strptime(ध्रुव वर्ण *buf, ध्रुव वर्ण *fmt, संरचना tm *tm);
#endif

#सचे !defined(HAVE_MKDTEMP)
पूर्णाङ्क mkstemps(वर्ण *path, पूर्णाङ्क slen);
पूर्णाङ्क mkstemp(वर्ण *path);
वर्ण *mkdtemp(वर्ण *path);
#endif

#define mkstemp(x) _ssh_mkstemp(x)
पूर्णाङ्क _ssh_mkstemp(वर्ण *);

#ifndef HAVE_DAEMON
पूर्णाङ्क daemon(पूर्णाङ्क nochdir, पूर्णाङ्क noclose);
#endif

#ifndef HAVE_DIRNAME
वर्ण *dirname(ध्रुव वर्ण *path);
#endif

#ifndef HAVE_FMT_SCALED
#define	FMT_SCALED_STRSIZE	7
पूर्णाङ्क	fmt_scaled(long long सङ्ख्या, वर्ण *result);
#endif

#ifndef HAVE_SCAN_SCALED
पूर्णाङ्क	scan_scaled(वर्ण *, long long *);
#endif

#सचे defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
वर्ण *inet_ntoa(संरचना in_addr in);
#endif

#ifndef HAVE_INET_NTOP
ध्रुव वर्ण *inet_ntop(पूर्णाङ्क af, ध्रुव शून्य *src, वर्ण *dst, socklen_t size);
#endif

#ifndef HAVE_INET_ATON
पूर्णाङ्क inet_aton(ध्रुव वर्ण *cp, संरचना in_addr *addr);
#endif

#ifndef HAVE_STRSEP
वर्ण *strsep(वर्ण **stringp, ध्रुव वर्ण *delim);
#endif

#ifndef HAVE_SETPROCTITLE
शून्य setproctitle(ध्रुव वर्ण *fmt, ...);
शून्य compat_init_setproctitle(पूर्णाङ्क argc, वर्ण *argv[]);
#endif

#ifndef HAVE_GETGROUPLIST
पूर्णाङ्क getgrouplist(ध्रुव वर्ण *, gid_t, gid_t *, पूर्णाङ्क *);
#endif

#सचे !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
पूर्णाङ्क BSDgetopt(पूर्णाङ्क argc, वर्ण * ध्रुव *argv, ध्रुव वर्ण *opts) __THROW;
#अन्तर्भाव "openbsd-compat/getopt.h"
#endif

#सचे ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# सचे defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
पूर्णाङ्क readv(पूर्णाङ्क, संरचना iovec *, पूर्णाङ्क);
# endif

# सचे defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
पूर्णाङ्क writev(पूर्णाङ्क, संरचना iovec *, पूर्णाङ्क);
# endif
#endif

/* Home grown routines */
#अन्तर्भाव "bsd-signal.h"
#अन्तर्भाव "bsd-misc.h"
#अन्तर्भाव "bsd-setres_id.h"
#अन्तर्भाव "bsd-statvfs.h"
#अन्तर्भाव "bsd-waitpid.h"
#अन्तर्भाव "bsd-poll.h"

#सचे defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
पूर्णाङ्क getpeereid(पूर्णाङ्क , uid_t *, gid_t *);
#endif

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(शून्य);
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_ARC4RANDOM_BUF
शून्य arc4random_buf(शून्य *, size_t);
#endif

#ifndef HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#endif

#ifndef HAVE_ASPRINTF
पूर्णाङ्क asprintf(वर्ण **, ध्रुव वर्ण *, ...);
#endif

#ifndef HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
पूर्णाङ्क openpty(पूर्णाङ्क *, पूर्णाङ्क *, वर्ण *, ध्रुव संरचना termios *,
    ध्रुव संरचना winsize *);
#endif /* HAVE_OPENPTY */

#ifndef HAVE_SNPRINTF
पूर्णाङ्क snprintf(वर्ण *, size_t, SNPRINTF_CONST वर्ण *, ...);
#endif

#ifndef HAVE_STRTOLL
long long strtoll(ध्रुव वर्ण *, वर्ण **, पूर्णाङ्क);
#endif

#ifndef HAVE_STRTOUL
unsigned long strtoul(ध्रुव वर्ण *, वर्ण **, पूर्णाङ्क);
#endif

#ifndef HAVE_STRTOULL
unsigned long long strtoull(ध्रुव वर्ण *, वर्ण **, पूर्णाङ्क);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(ध्रुव वर्ण *, long long, long long, ध्रुव वर्ण **);
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
पूर्णाङ्क mbtowc(wchar_t *, ध्रुव वर्ण*, size_t);
#endif

#सचे !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
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
# अञ्ञथा
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  अञ्ञथा
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#endif

#ifndef HAVE_VASPRINTF
पूर्णाङ्क vasprintf(वर्ण **, ध्रुव वर्ण *, va_list);
#endif

#ifndef HAVE_VSNPRINTF
पूर्णाङ्क vsnprintf(वर्ण *, size_t, ध्रुव वर्ण *, va_list);
#endif

#ifndef HAVE_USER_FROM_UID
वर्ण *user_from_uid(uid_t, पूर्णाङ्क);
#endif

#ifndef HAVE_GROUP_FROM_GID
वर्ण *group_from_gid(gid_t, पूर्णाङ्क);
#endif

#ifndef HAVE_TIMINGSAFE_BCMP
पूर्णाङ्क timingsafe_bcmp(ध्रुव शून्य *, ध्रुव शून्य *, size_t);
#endif

#ifndef HAVE_BCRYPT_PBKDF
पूर्णाङ्क	bcrypt_pbkdf(ध्रुव वर्ण *, size_t, ध्रुव uint8_t *, size_t,
    uint8_t *, size_t, unsigned पूर्णाङ्क);
#endif

#ifndef HAVE_EXPLICIT_BZERO
शून्य explicit_bzero(शून्य *p, size_t n);
#endif

#ifndef HAVE_FREEZERO
शून्य freezero(शून्य *, size_t);
#endif

#ifndef HAVE_LOCALTIME_R
संरचना tm *localtime_r(ध्रुव time_t *, संरचना tm *);
#endif

#ifndef HAVE_TIMEGM
#अन्तर्भाव <time.h>
time_t timegm(संरचना tm *);
#endif

वर्ण *xcrypt(ध्रुव वर्ण *password, ध्रुव वर्ण *salt);
वर्ण *shadow_pw(संरचना passwd *pw);

/* rfc2553 socket API replacements */
#अन्तर्भाव "fake-rfc2553.h"

/* Routines for a single OS platform */
#अन्तर्भाव "bsd-cygwin_util.h"

#अन्तर्भाव "port-aix.h"
#अन्तर्भाव "port-irix.h"
#अन्तर्भाव "port-linux.h"
#अन्तर्भाव "port-solaris.h"
#अन्तर्भाव "port-net.h"
#अन्तर्भाव "port-uw.h"

/* _FORTIFY_SOURCE breaks FD_ISSET(n)/FD_SET(n) for n > FD_SETSIZE. Avoid. */
#सचे defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# सचे defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  सचे __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, set)	kludge_FD_SET(n, set)
#   define FD_ISSET(n, set)	kludge_FD_ISSET(n, set)
शून्य kludge_FD_SET(पूर्णाङ्क, fd_set *);
पूर्णाङ्क kludge_FD_ISSET(पूर्णाङ्क, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#endif /* _OPENBSD_COMPAT_H */
