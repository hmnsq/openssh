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

#अगर_अघोषित _OPENBSD_COMPAT_H
#घोषणा _OPENBSD_COMPAT_H

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <pwd.h>

#समावेश <sys/socket.h>

#समावेश <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#समावेश "base64.h"
#समावेश "sigact.h"
#समावेश "readpassphrase.h"
#समावेश "vis.h"
#समावेश "getrrsetbyname.h"
#समावेश "sha1.h"
#समावेश "bsd-sha2.h"
#समावेश "md5.h"
#समावेश "blf.h"
#समावेश "fnmatch.h"

#अगर_अघोषित __THROW
# अगर defined __cplusplus
#  define __THROW throw()
# अन्यथा
#  define __THROW
# endif
#पूर्ण_अगर

#अगर defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#पूर्ण_अगर

#अगर_अघोषित HAVE_BASENAME
अक्षर *basename(स्थिर अक्षर *path);
#पूर्ण_अगर

#अगर_अघोषित HAVE_BINDRESVPORT_SA
पूर्णांक bindresvport_sa(पूर्णांक sd, काष्ठा sockaddr *sa);
#पूर्ण_अगर

#अगर_अघोषित HAVE_CLOSEFROM
व्योम closefrom(पूर्णांक);
#पूर्ण_अगर

#अगर defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
पूर्णांक ftruncate(पूर्णांक filedes, off_t लंबाई);
#पूर्ण_अगर

#अगर_अघोषित HAVE_GETLINE
#समावेश <stdio.h>
ssize_t getline(अक्षर **, माप_प्रकार *, खाता *);
#पूर्ण_अगर

#अगर_अघोषित HAVE_GETPAGESIZE
पूर्णांक getpagesize(व्योम);
#पूर्ण_अगर

#अगर_अघोषित HAVE_GETCWD
अक्षर *getcwd(अक्षर *pt, माप_प्रकार आकार);
#पूर्ण_अगर

#अगर_अघोषित HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#घोषणा getexecpath(a, b) (-1)
#पूर्ण_अगर

#अगर_अघोषित HAVE_KILLPG
पूर्णांक killpg(pid_t, पूर्णांक);
#पूर्ण_अगर

#अगर defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
व्योम *memmem(स्थिर व्योम *, माप_प्रकार, स्थिर व्योम *, माप_प्रकार);
#पूर्ण_अगर

#अगर_अघोषित HAVE_REALLOCARRAY
व्योम *reallocarray(व्योम *, माप_प्रकार, माप_प्रकार);
#पूर्ण_अगर

#अगर_अघोषित HAVE_RECALLOCARRAY
व्योम *recallocarray(व्योम *, माप_प्रकार, माप_प्रकार, माप_प्रकार);
#पूर्ण_अगर

#अगर_अघोषित HAVE_RRESVPORT_AF
पूर्णांक rresvport_af(पूर्णांक *alport, sa_family_t af);
#पूर्ण_अगर

#अगर_अघोषित HAVE_STRLCPY
माप_प्रकार strlcpy(अक्षर *dst, स्थिर अक्षर *src, माप_प्रकार siz);
#पूर्ण_अगर

#अगर_अघोषित HAVE_STRLCAT
माप_प्रकार strlcat(अक्षर *dst, स्थिर अक्षर *src, माप_प्रकार siz);
#पूर्ण_अगर

#अगर_अघोषित HAVE_STRCASESTR
अक्षर *strcasestr(स्थिर अक्षर *, स्थिर अक्षर *);
#पूर्ण_अगर

#अगर_अघोषित HAVE_STRNLEN
माप_प्रकार strnlen(स्थिर अक्षर *, माप_प्रकार);
#पूर्ण_अगर

#अगर_अघोषित HAVE_STRNDUP
अक्षर *strndup(स्थिर अक्षर *s, माप_प्रकार n);
#पूर्ण_अगर

#अगर_अघोषित HAVE_SETENV
पूर्णांक setenv(रेजिस्टर स्थिर अक्षर *name, रेजिस्टर स्थिर अक्षर *मूल्य, पूर्णांक rewrite);
#पूर्ण_अगर

#अगर_अघोषित HAVE_STRMODE
व्योम strmode(पूर्णांक mode, अक्षर *p);
#पूर्ण_अगर

#अगर_अघोषित HAVE_STRPTIME
#समावेश  <time.h>
अक्षर *strptime(स्थिर अक्षर *buf, स्थिर अक्षर *fmt, काष्ठा पंचांग *पंचांग);
#पूर्ण_अगर

#अगर !defined(HAVE_MKDTEMP)
पूर्णांक mkstemps(अक्षर *path, पूर्णांक slen);
पूर्णांक mkstemp(अक्षर *path);
अक्षर *mkdtemp(अक्षर *path);
#पूर्ण_अगर

#घोषणा mkstemp(x) _ssh_mkstemp(x)
पूर्णांक _ssh_mkstemp(अक्षर *);

#अगर_अघोषित HAVE_DAEMON
पूर्णांक daemon(पूर्णांक nochdir, पूर्णांक noclose);
#पूर्ण_अगर

#अगर_अघोषित HAVE_DIRNAME
अक्षर *स_नाम(स्थिर अक्षर *path);
#पूर्ण_अगर

#अगर_अघोषित HAVE_FMT_SCALED
#घोषणा	FMT_SCALED_STRSIZE	7
पूर्णांक	fmt_scaled(दीर्घ दीर्घ संख्या, अक्षर *परिणाम);
#पूर्ण_अगर

#अगर_अघोषित HAVE_SCAN_SCALED
पूर्णांक	scan_scaled(अक्षर *, दीर्घ दीर्घ *);
#पूर्ण_अगर

#अगर defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
अक्षर *inet_ntoa(काष्ठा in_addr in);
#पूर्ण_अगर

#अगर_अघोषित HAVE_INET_NTOP
स्थिर अक्षर *inet_ntop(पूर्णांक af, स्थिर व्योम *src, अक्षर *dst, socklen_t आकार);
#पूर्ण_अगर

#अगर_अघोषित HAVE_INET_ATON
पूर्णांक inet_aton(स्थिर अक्षर *cp, काष्ठा in_addr *addr);
#पूर्ण_अगर

#अगर_अघोषित HAVE_STRSEP
अक्षर *strsep(अक्षर **stringp, स्थिर अक्षर *delim);
#पूर्ण_अगर

#अगर_अघोषित HAVE_SETPROCTITLE
व्योम setproctitle(स्थिर अक्षर *fmt, ...);
व्योम compat_init_setproctitle(पूर्णांक argc, अक्षर *argv[]);
#पूर्ण_अगर

#अगर_अघोषित HAVE_GETGROUPLIST
पूर्णांक getgrouplist(स्थिर अक्षर *, gid_t, gid_t *, पूर्णांक *);
#पूर्ण_अगर

#अगर !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
पूर्णांक BSDgetopt(पूर्णांक argc, अक्षर * स्थिर *argv, स्थिर अक्षर *opts) __THROW;
#समावेश "openbsd-compat/getopt.h"
#पूर्ण_अगर

#अगर ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# अगर defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
पूर्णांक readv(पूर्णांक, काष्ठा iovec *, पूर्णांक);
# endif

# अगर defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
पूर्णांक writev(पूर्णांक, काष्ठा iovec *, पूर्णांक);
# endif
#पूर्ण_अगर

/* Home grown routines */
#समावेश "bsd-signal.h"
#समावेश "bsd-misc.h"
#समावेश "bsd-setres_id.h"
#समावेश "bsd-statvfs.h"
#समावेश "bsd-waitpid.h"
#समावेश "bsd-poll.h"

#अगर defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
पूर्णांक getpeereid(पूर्णांक , uid_t *, gid_t *);
#पूर्ण_अगर

#अगर_अघोषित HAVE_ARC4RANDOM
uint32_t arc4random(व्योम);
#पूर्ण_अगर /* !HAVE_ARC4RANDOM */

#अगर_अघोषित HAVE_ARC4RANDOM_BUF
व्योम arc4random_buf(व्योम *, माप_प्रकार);
#पूर्ण_अगर

#अगर_अघोषित HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#पूर्ण_अगर

#अगर_अघोषित HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#पूर्ण_अगर

#अगर_अघोषित HAVE_ASPRINTF
पूर्णांक asprintf(अक्षर **, स्थिर अक्षर *, ...);
#पूर्ण_अगर

#अगर_अघोषित HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
पूर्णांक openpty(पूर्णांक *, पूर्णांक *, अक्षर *, स्थिर काष्ठा termios *,
    स्थिर काष्ठा winsize *);
#पूर्ण_अगर /* HAVE_OPENPTY */

#अगर_अघोषित HAVE_SNPRINTF
पूर्णांक snprintf(अक्षर *, माप_प्रकार, SNPRINTF_CONST अक्षर *, ...);
#पूर्ण_अगर

#अगर_अघोषित HAVE_STRTOLL
दीर्घ दीर्घ strtoll(स्थिर अक्षर *, अक्षर **, पूर्णांक);
#पूर्ण_अगर

#अगर_अघोषित HAVE_STRTOUL
अचिन्हित दीर्घ म_से_अदीर्घ(स्थिर अक्षर *, अक्षर **, पूर्णांक);
#पूर्ण_अगर

#अगर_अघोषित HAVE_STRTOULL
अचिन्हित दीर्घ दीर्घ strtoull(स्थिर अक्षर *, अक्षर **, पूर्णांक);
#पूर्ण_अगर

#अगर_अघोषित HAVE_STRTONUM
दीर्घ दीर्घ strtonum(स्थिर अक्षर *, दीर्घ दीर्घ, दीर्घ दीर्घ, स्थिर अक्षर **);
#पूर्ण_अगर

/* multibyte character support */
#अगर_अघोषित HAVE_MBLEN
# define mblen(x, y)	(1)
#पूर्ण_अगर

#अगर_अघोषित HAVE_WCWIDTH
# define wcwidth(x)	(((x) >= 0x20 && (x) <= 0x7e) ? 1 : -1)
/* force our no-op nl_langinfo and mbtowc */
# undef HAVE_NL_LANGINFO
# undef HAVE_MBTOWC
# undef HAVE_LANGINFO_H
#पूर्ण_अगर

#अगर_अघोषित HAVE_NL_LANGINFO
# define nl_langinfo(x)	""
#पूर्ण_अगर

#अगर_अघोषित HAVE_MBTOWC
पूर्णांक mbtowc(ब_अक्षर_प्रकार *, स्थिर अक्षर*, माप_प्रकार);
#पूर्ण_अगर

#अगर !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
# include <stdarg.h>
#पूर्ण_अगर

/*
 * Some platforms unconditionally undefine va_copy() so we define VA_COPY()
 * instead.  This is known to be the case on at least some configurations of
 * AIX with the xlc compiler.
 */
#अगर_अघोषित VA_COPY
# ifdef HAVE_VA_COPY
#  define VA_COPY(dest, src) va_copy(dest, src)
# अन्यथा
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  अन्यथा
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#पूर्ण_अगर

#अगर_अघोषित HAVE_VASPRINTF
पूर्णांक vasprintf(अक्षर **, स्थिर अक्षर *, बहु_सूची);
#पूर्ण_अगर

#अगर_अघोषित HAVE_VSNPRINTF
पूर्णांक vsnprintf(अक्षर *, माप_प्रकार, स्थिर अक्षर *, बहु_सूची);
#पूर्ण_अगर

#अगर_अघोषित HAVE_USER_FROM_UID
अक्षर *user_from_uid(uid_t, पूर्णांक);
#पूर्ण_अगर

#अगर_अघोषित HAVE_GROUP_FROM_GID
अक्षर *group_from_gid(gid_t, पूर्णांक);
#पूर्ण_अगर

#अगर_अघोषित HAVE_TIMINGSAFE_BCMP
पूर्णांक timingsafe_bcmp(स्थिर व्योम *, स्थिर व्योम *, माप_प्रकार);
#पूर्ण_अगर

#अगर_अघोषित HAVE_BCRYPT_PBKDF
पूर्णांक	bcrypt_pbkdf(स्थिर अक्षर *, माप_प्रकार, स्थिर uint8_t *, माप_प्रकार,
    uint8_t *, माप_प्रकार, अचिन्हित पूर्णांक);
#पूर्ण_अगर

#अगर_अघोषित HAVE_EXPLICIT_BZERO
व्योम explicit_bzero(व्योम *p, माप_प्रकार n);
#पूर्ण_अगर

#अगर_अघोषित HAVE_FREEZERO
व्योम freezero(व्योम *, माप_प्रकार);
#पूर्ण_अगर

#अगर_अघोषित HAVE_LOCALTIME_R
काष्ठा पंचांग *localtime_r(स्थिर समय_प्रकार *, काष्ठा पंचांग *);
#पूर्ण_अगर

#अगर_अघोषित HAVE_TIMEGM
#समावेश <time.h>
समय_प्रकार timegm(काष्ठा पंचांग *);
#पूर्ण_अगर

अक्षर *xcrypt(स्थिर अक्षर *password, स्थिर अक्षर *salt);
अक्षर *shadow_pw(काष्ठा passwd *pw);

/* rfc2553 socket API replacements */
#समावेश "fake-rfc2553.h"

/* Routines for a single OS platform */
#समावेश "bsd-cygwin_util.h"

#समावेश "port-aix.h"
#समावेश "port-irix.h"
#समावेश "port-linux.h"
#समावेश "port-solaris.h"
#समावेश "port-net.h"
#समावेश "port-uw.h"

/* _FORTIFY_SOURCE breaks FD_ISSET(n)/FD_SET(n) for n > FD_SETSIZE. Avoid. */
#अगर defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# अगर defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  अगर __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, set)	kludge_FD_SET(n, set)
#   define FD_ISSET(n, set)	kludge_FD_ISSET(n, set)
व्योम kludge_FD_SET(पूर्णांक, fd_set *);
पूर्णांक kludge_FD_ISSET(पूर्णांक, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#पूर्ण_अगर /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#पूर्ण_अगर /* _OPENBSD_COMPAT_H */
