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

#यदि_अपरिभाषितम् _OPENBSD_COMPAT_H
#परिभाषय _OPENBSD_COMPAT_H

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

#यदि_अपरिभाषितम् __THROW
# यदि defined __cplusplus
#  define __THROW throw()
# अन्यथा
#  define __THROW
# endif
#यदि_अन्तः

#यदि defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_BASENAME
वर्ण *basename(ध्रुव वर्ण *मार्गः);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_BINDRESVPORT_SA
पूर्णाङ्क bindresvport_sa(पूर्णाङ्क sd, संरचना sockaddr *sa);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_CLOSEFROM
शून्य closefrom(पूर्णाङ्क);
#यदि_अन्तः

#यदि defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
पूर्णाङ्क ftruncate(पूर्णाङ्क filedes, off_t दीर्घता);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_GETLINE
#अन्तर्भाव <stdio.h>
ssize_t getline(वर्ण **, आकार_t *, FILE *);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_GETPAGESIZE
पूर्णाङ्क getpagesize(शून्य);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_GETCWD
वर्ण *getcwd(वर्ण *pt, आकार_t आकार);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#परिभाषय getexecpath(a, b) (-1)
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_KILLPG
पूर्णाङ्क killpg(pid_t, पूर्णाङ्क);
#यदि_अन्तः

#यदि defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
शून्य *memmem(ध्रुव शून्य *, आकार_t, ध्रुव शून्य *, आकार_t);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_REALLOCARRAY
शून्य *reallocarray(शून्य *, आकार_t, आकार_t);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_RECALLOCARRAY
शून्य *recallocarray(शून्य *, आकार_t, आकार_t, आकार_t);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_RRESVPORT_AF
पूर्णाङ्क rresvport_af(पूर्णाङ्क *alport, sa_family_t af);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_STRLCPY
आकार_t strlcpy(वर्ण *dst, ध्रुव वर्ण *src, आकार_t siz);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_STRLCAT
आकार_t strlcat(वर्ण *dst, ध्रुव वर्ण *src, आकार_t siz);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_STRCASESTR
वर्ण *strcasestr(ध्रुव वर्ण *, ध्रुव वर्ण *);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_STRNLEN
आकार_t strnlen(ध्रुव वर्ण *, आकार_t);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_STRNDUP
वर्ण *strndup(ध्रुव वर्ण *s, आकार_t n);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_SETENV
पूर्णाङ्क setenv(पञ्जिका ध्रुव वर्ण *name, पञ्जिका ध्रुव वर्ण *मानम्, पूर्णाङ्क rewrite);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_STRMODE
शून्य strmode(पूर्णाङ्क बहुलकम्, वर्ण *p);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_STRPTIME
#अन्तर्भाव  <time.h>
वर्ण *strptime(ध्रुव वर्ण *buf, ध्रुव वर्ण *fmt, संरचना tm *tm);
#यदि_अन्तः

#यदि !defined(HAVE_MKDTEMP)
पूर्णाङ्क mkstemps(वर्ण *मार्गः, पूर्णाङ्क slen);
पूर्णाङ्क mkstemp(वर्ण *मार्गः);
वर्ण *mkdtemp(वर्ण *मार्गः);
#यदि_अन्तः

#परिभाषय mkstemp(x) _ssh_mkstemp(x)
पूर्णाङ्क _ssh_mkstemp(वर्ण *);

#यदि_अपरिभाषितम् HAVE_DAEMON
पूर्णाङ्क daemon(पूर्णाङ्क nochdir, पूर्णाङ्क noclose);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_DIRNAME
वर्ण *dirname(ध्रुव वर्ण *मार्गः);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_FMT_SCALED
#परिभाषय	FMT_SCALED_STRSIZE	7
पूर्णाङ्क	fmt_scaled(दीर्घ दीर्घ सङ्ख्या, वर्ण *परिणाम);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_अवलोकनम्_SCALED
पूर्णाङ्क	अवलोकनम्_scaled(वर्ण *, दीर्घ दीर्घ *);
#यदि_अन्तः

#यदि defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
वर्ण *inet_ntoa(संरचना in_addr अन्तर्);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_INET_NTOP
ध्रुव वर्ण *inet_ntop(पूर्णाङ्क af, ध्रुव शून्य *src, वर्ण *dst, socklen_t आकार);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_INET_ATON
पूर्णाङ्क inet_aton(ध्रुव वर्ण *cp, संरचना in_addr *addr);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_STRSEP
वर्ण *strsep(वर्ण **stringp, ध्रुव वर्ण *delim);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_SETPROCTITLE
शून्य setproctitle(ध्रुव वर्ण *fmt, ...);
शून्य compat_init_setproctitle(पूर्णाङ्क argc, वर्ण *argv[]);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_GETGROUPLIST
पूर्णाङ्क getgrouplist(ध्रुव वर्ण *, gid_t, gid_t *, पूर्णाङ्क *);
#यदि_अन्तः

#यदि !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
पूर्णाङ्क BSDgetopt(पूर्णाङ्क argc, वर्ण * ध्रुव *argv, ध्रुव वर्ण *opts) __THROW;
#अन्तर्भाव "openbsd-compat/getopt.h"
#यदि_अन्तः

#यदि ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# यदि defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
पूर्णाङ्क readv(पूर्णाङ्क, संरचना iovec *, पूर्णाङ्क);
# endif

# यदि defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
पूर्णाङ्क writev(पूर्णाङ्क, संरचना iovec *, पूर्णाङ्क);
# endif
#यदि_अन्तः

/* Home grown routines */
#अन्तर्भाव "bsd-signal.h"
#अन्तर्भाव "bsd-misc.h"
#अन्तर्भाव "bsd-setres_id.h"
#अन्तर्भाव "bsd-statvfs.h"
#अन्तर्भाव "bsd-waitpid.h"
#अन्तर्भाव "bsd-poll.h"

#यदि defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
पूर्णाङ्क getpeereid(पूर्णाङ्क , uid_t *, gid_t *);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_ARC4RANDOM
uint32_t arc4random(शून्य);
#यदि_अन्तः /* !HAVE_ARC4RANDOM */

#यदि_अपरिभाषितम् HAVE_ARC4RANDOM_BUF
शून्य arc4random_buf(शून्य *, आकार_t);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_ARC4_RANDOM_एकरूपम्
uint32_t arc4random_एकरूपम्(uint32_t);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_ASPRINTF
पूर्णाङ्क asprintf(वर्ण **, ध्रुव वर्ण *, ...);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
पूर्णाङ्क openpty(पूर्णाङ्क *, पूर्णाङ्क *, वर्ण *, ध्रुव संरचना termios *,
    ध्रुव संरचना winsize *);
#यदि_अन्तः /* HAVE_OPENPTY */

#यदि_अपरिभाषितम् HAVE_SNPRINTF
पूर्णाङ्क snprintf(वर्ण *, आकार_t, SNPRINTF_CONST वर्ण *, ...);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_STRTOLL
दीर्घ दीर्घ strtoll(ध्रुव वर्ण *, वर्ण **, पूर्णाङ्क);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_STRTOUL
अचिह्नित दीर्घ strtoul(ध्रुव वर्ण *, वर्ण **, पूर्णाङ्क);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_STRTOULL
अचिह्नित दीर्घ दीर्घ strtoull(ध्रुव वर्ण *, वर्ण **, पूर्णाङ्क);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_STRTONUM
दीर्घ दीर्घ strtonum(ध्रुव वर्ण *, दीर्घ दीर्घ, दीर्घ दीर्घ, ध्रुव वर्ण **);
#यदि_अन्तः

/* multibyte character support */
#यदि_अपरिभाषितम् HAVE_MBLEN
# define mblen(x, y)	(1)
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_WCWIDTH
# define wcwidth(x)	(((x) >= 0x20 && (x) <= 0x7e) ? 1 : -1)
/* force our no-op nl_langinfo and mbtowc */
# undef HAVE_NL_LANGINFO
# undef HAVE_MBTOWC
# undef HAVE_LANGINFO_H
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_NL_LANGINFO
# define nl_langinfo(x)	""
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_MBTOWC
पूर्णाङ्क mbtowc(wchar_t *, ध्रुव वर्ण*, आकार_t);
#यदि_अन्तः

#यदि !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
# include <stdarg.h>
#यदि_अन्तः

/*
 * Some platforms unconditionally undefine va_copy() so we define VA_COPY()
 * instead.  This is known to be the case on at least some configurations of
 * AIX with the xlc compiler.
 */
#यदि_अपरिभाषितम् VA_COPY
# ifdef HAVE_VA_COPY
#  define VA_COPY(dest, src) va_copy(dest, src)
# अन्यथा
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  अन्यथा
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_VASPRINTF
पूर्णाङ्क vasprintf(वर्ण **, ध्रुव वर्ण *, va_list);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_VSNPRINTF
पूर्णाङ्क vsnprintf(वर्ण *, आकार_t, ध्रुव वर्ण *, va_list);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_USER_FROM_UID
वर्ण *user_from_uid(uid_t, पूर्णाङ्क);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_गणः_FROM_GID
वर्ण *गणः_from_gid(gid_t, पूर्णाङ्क);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_TIMINGSAFE_BCMP
पूर्णाङ्क timingsafe_bcmp(ध्रुव शून्य *, ध्रुव शून्य *, आकार_t);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_BCRYPT_PBKDF
पूर्णाङ्क	bcrypt_pbkdf(ध्रुव वर्ण *, आकार_t, ध्रुव uint8_t *, आकार_t,
    uint8_t *, आकार_t, अचिह्नित पूर्णाङ्क);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_EXPLICIT_BZERO
शून्य explicit_bzero(शून्य *p, आकार_t n);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_FREEZERO
शून्य freezero(शून्य *, आकार_t);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_LOCALTIME_R
संरचना tm *localtime_r(ध्रुव time_t *, संरचना tm *);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_TIMEGM
#अन्तर्भाव <time.h>
time_t timegm(संरचना tm *);
#यदि_अन्तः

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
#यदि defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# यदि defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  यदि __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, समुच्चयः)	kludge_FD_समुच्चयः(n, समुच्चयः)
#   define FD_ISSET(n, समुच्चयः)	kludge_FD_ISSET(n, समुच्चयः)
शून्य kludge_FD_समुच्चयः(पूर्णाङ्क, fd_set *);
पूर्णाङ्क kludge_FD_ISSET(पूर्णाङ्क, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#यदि_अन्तः /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#यदि_अन्तः /* _OPENBSD_COMPAT_H */
