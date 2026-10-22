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
# जर defined __cplusplus
#  define __THROW throw()
# अन्यथा
#  define __THROW
# endif
#endif

#जर defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#endif

#ifndef HAVE_BASENAME
अक्षर *basename(स्थिरांक अक्षर *path);
#endif

#ifndef HAVE_BINDRESVPORT_SA
पूर्णांक bindresvport_sa(पूर्णांक sd, संरचना sockaddr *sa);
#endif

#ifndef HAVE_CLOSEFROM
शून्य closefrom(पूर्णांक);
#endif

#जर defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
पूर्णांक ftruncate(पूर्णांक filedes, off_t length);
#endif

#ifndef HAVE_GETLINE
#अन्तर्भाव <stdio.h>
ssize_t getline(अक्षर **, माप_प्रकार *, खाता *);
#endif

#ifndef HAVE_GETPAGESIZE
पूर्णांक getpagesize(शून्य);
#endif

#ifndef HAVE_GETCWD
अक्षर *getcwd(अक्षर *pt, माप_प्रकार size);
#endif

#ifndef HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#define getexecpath(a, b) (-1)
#endif

#ifndef HAVE_KILLPG
पूर्णांक killpg(pid_t, पूर्णांक);
#endif

#जर defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
शून्य *memmem(स्थिरांक शून्य *, माप_प्रकार, स्थिरांक शून्य *, माप_प्रकार);
#endif

#ifndef HAVE_REALLOCARRAY
शून्य *reallocarray(शून्य *, माप_प्रकार, माप_प्रकार);
#endif

#ifndef HAVE_RECALLOCARRAY
शून्य *recallocarray(शून्य *, माप_प्रकार, माप_प्रकार, माप_प्रकार);
#endif

#ifndef HAVE_RRESVPORT_AF
पूर्णांक rresvport_af(पूर्णांक *alport, sa_family_t af);
#endif

#ifndef HAVE_STRLCPY
माप_प्रकार strlcpy(अक्षर *dst, स्थिरांक अक्षर *src, माप_प्रकार siz);
#endif

#ifndef HAVE_STRLCAT
माप_प्रकार strlcat(अक्षर *dst, स्थिरांक अक्षर *src, माप_प्रकार siz);
#endif

#ifndef HAVE_STRCASESTR
अक्षर *strcasestr(स्थिरांक अक्षर *, स्थिरांक अक्षर *);
#endif

#ifndef HAVE_STRNLEN
माप_प्रकार strnlen(स्थिरांक अक्षर *, माप_प्रकार);
#endif

#ifndef HAVE_STRNDUP
अक्षर *strndup(स्थिरांक अक्षर *s, माप_प्रकार n);
#endif

#ifndef HAVE_SETENV
पूर्णांक setenv(नोंदणी स्थिरांक अक्षर *name, नोंदणी स्थिरांक अक्षर *मूल्य, पूर्णांक rewrite);
#endif

#ifndef HAVE_STRMODE
शून्य strmode(पूर्णांक mode, अक्षर *p);
#endif

#ifndef HAVE_STRPTIME
#अन्तर्भाव  <time.h>
अक्षर *strptime(स्थिरांक अक्षर *buf, स्थिरांक अक्षर *fmt, संरचना पंचांग *पंचांग);
#endif

#जर !defined(HAVE_MKDTEMP)
पूर्णांक mkstemps(अक्षर *path, पूर्णांक slen);
पूर्णांक mkstemp(अक्षर *path);
अक्षर *mkdtemp(अक्षर *path);
#endif

#define mkstemp(x) _ssh_mkstemp(x)
पूर्णांक _ssh_mkstemp(अक्षर *);

#ifndef HAVE_DAEMON
पूर्णांक daemon(पूर्णांक nochdir, पूर्णांक noclose);
#endif

#ifndef HAVE_DIRNAME
अक्षर *स_नाम(स्थिरांक अक्षर *path);
#endif

#ifndef HAVE_FMT_SCALED
#define	FMT_SCALED_STRSIZE	7
पूर्णांक	fmt_scaled(दीर्घ दीर्घ संख्या, अक्षर *result);
#endif

#ifndef HAVE_SCAN_SCALED
पूर्णांक	scan_scaled(अक्षर *, दीर्घ दीर्घ *);
#endif

#जर defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
अक्षर *inet_ntoa(संरचना in_addr in);
#endif

#ifndef HAVE_INET_NTOP
स्थिरांक अक्षर *inet_ntop(पूर्णांक af, स्थिरांक शून्य *src, अक्षर *dst, socklen_t size);
#endif

#ifndef HAVE_INET_ATON
पूर्णांक inet_aton(स्थिरांक अक्षर *cp, संरचना in_addr *addr);
#endif

#ifndef HAVE_STRSEP
अक्षर *strsep(अक्षर **stringp, स्थिरांक अक्षर *delim);
#endif

#ifndef HAVE_SETPROCTITLE
शून्य setproctitle(स्थिरांक अक्षर *fmt, ...);
शून्य compat_init_setproctitle(पूर्णांक argc, अक्षर *argv[]);
#endif

#ifndef HAVE_GETGROUPLIST
पूर्णांक getgrouplist(स्थिरांक अक्षर *, gid_t, gid_t *, पूर्णांक *);
#endif

#जर !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
पूर्णांक BSDgetopt(पूर्णांक argc, अक्षर * स्थिरांक *argv, स्थिरांक अक्षर *opts) __THROW;
#अन्तर्भाव "openbsd-compat/getopt.h"
#endif

#जर ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# जर defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
पूर्णांक readv(पूर्णांक, संरचना iovec *, पूर्णांक);
# endif

# जर defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
पूर्णांक writev(पूर्णांक, संरचना iovec *, पूर्णांक);
# endif
#endif

/* Home grown routines */
#अन्तर्भाव "bsd-signal.h"
#अन्तर्भाव "bsd-misc.h"
#अन्तर्भाव "bsd-setres_id.h"
#अन्तर्भाव "bsd-statvfs.h"
#अन्तर्भाव "bsd-waitpid.h"
#अन्तर्भाव "bsd-poll.h"

#जर defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
पूर्णांक getpeereid(पूर्णांक , uid_t *, gid_t *);
#endif

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(शून्य);
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_ARC4RANDOM_BUF
शून्य arc4random_buf(शून्य *, माप_प्रकार);
#endif

#ifndef HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#endif

#ifndef HAVE_ASPRINTF
पूर्णांक asprintf(अक्षर **, स्थिरांक अक्षर *, ...);
#endif

#ifndef HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
पूर्णांक openpty(पूर्णांक *, पूर्णांक *, अक्षर *, स्थिरांक संरचना termios *,
    स्थिरांक संरचना winsize *);
#endif /* HAVE_OPENPTY */

#ifndef HAVE_SNPRINTF
पूर्णांक snprintf(अक्षर *, माप_प्रकार, SNPRINTF_CONST अक्षर *, ...);
#endif

#ifndef HAVE_STRTOLL
दीर्घ दीर्घ strtoll(स्थिरांक अक्षर *, अक्षर **, पूर्णांक);
#endif

#ifndef HAVE_STRTOUL
अचिन्हित दीर्घ म_से_अदीर्घ(स्थिरांक अक्षर *, अक्षर **, पूर्णांक);
#endif

#ifndef HAVE_STRTOULL
अचिन्हित दीर्घ दीर्घ strtoull(स्थिरांक अक्षर *, अक्षर **, पूर्णांक);
#endif

#ifndef HAVE_STRTONUM
दीर्घ दीर्घ strtonum(स्थिरांक अक्षर *, दीर्घ दीर्घ, दीर्घ दीर्घ, स्थिरांक अक्षर **);
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
पूर्णांक mbtowc(ब_अक्षर_प्रकार *, स्थिरांक अक्षर*, माप_प्रकार);
#endif

#जर !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
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
# अन्यथा
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  अन्यथा
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#endif

#ifndef HAVE_VASPRINTF
पूर्णांक vasprintf(अक्षर **, स्थिरांक अक्षर *, बहु_सूची);
#endif

#ifndef HAVE_VSNPRINTF
पूर्णांक vsnprintf(अक्षर *, माप_प्रकार, स्थिरांक अक्षर *, बहु_सूची);
#endif

#ifndef HAVE_USER_FROM_UID
अक्षर *user_from_uid(uid_t, पूर्णांक);
#endif

#ifndef HAVE_GROUP_FROM_GID
अक्षर *group_from_gid(gid_t, पूर्णांक);
#endif

#ifndef HAVE_TIMINGSAFE_BCMP
पूर्णांक timingsafe_bcmp(स्थिरांक शून्य *, स्थिरांक शून्य *, माप_प्रकार);
#endif

#ifndef HAVE_BCRYPT_PBKDF
पूर्णांक	bcrypt_pbkdf(स्थिरांक अक्षर *, माप_प्रकार, स्थिरांक uint8_t *, माप_प्रकार,
    uint8_t *, माप_प्रकार, अचिन्हित पूर्णांक);
#endif

#ifndef HAVE_EXPLICIT_BZERO
शून्य explicit_bzero(शून्य *p, माप_प्रकार n);
#endif

#ifndef HAVE_FREEZERO
शून्य freezero(शून्य *, माप_प्रकार);
#endif

#ifndef HAVE_LOCALTIME_R
संरचना पंचांग *localtime_r(स्थिरांक समय_प्रकार *, संरचना पंचांग *);
#endif

#ifndef HAVE_TIMEGM
#अन्तर्भाव <time.h>
समय_प्रकार timegm(संरचना पंचांग *);
#endif

अक्षर *xcrypt(स्थिरांक अक्षर *password, स्थिरांक अक्षर *salt);
अक्षर *shadow_pw(संरचना passwd *pw);

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
#जर defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# जर defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  जर __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, set)	kludge_FD_SET(n, set)
#   define FD_ISSET(n, set)	kludge_FD_ISSET(n, set)
शून्य kludge_FD_SET(पूर्णांक, fd_set *);
पूर्णांक kludge_FD_ISSET(पूर्णांक, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#endif /* _OPENBSD_COMPAT_H */
