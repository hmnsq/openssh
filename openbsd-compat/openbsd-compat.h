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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _OPENBSD_COMPAT_H
#ವ್ಯಾಖ್ಯಾನಿಸು _OPENBSD_COMPAT_H

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>

#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ಅನ್ತರ್ಭಾವ <stddef.h>  /* for wchar_t */

/* OpenBSD function replacements */
#ಅನ್ತರ್ಭಾವ "base64.h"
#ಅನ್ತರ್ಭಾವ "sigact.h"
#ಅನ್ತರ್ಭಾವ "readpassphrase.h"
#ಅನ್ತರ್ಭಾವ "vis.h"
#ಅನ್ತರ್ಭಾವ "getrrsetbyname.h"
#ಅನ್ತರ್ಭಾವ "sha1.h"
#ಅನ್ತರ್ಭಾವ "bsd-sha2.h"
#ಅನ್ತರ್ಭಾವ "md5.h"
#ಅನ್ತರ್ಭಾವ "blf.h"
#ಅನ್ತರ್ಭಾವ "fnmatch.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ __THROW
# ಆದರೆ defined __cplusplus
#  define __THROW throw()
# ಇಲ್ಲದಿದ್ದರೆ
#  define __THROW
# endif
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_LOGIN_CAP) && !defined(HAVE_LOGIN_GETPWCLASS)
# include <login_cap.h>
# define login_getpwclass(pw) login_getclass(pw->pw_class)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_BASENAME
ಅಕ್ಷರ *basename(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_BINDRESVPORT_SA
ಪೂರ್ಣಾಂಕ bindresvport_sa(ಪೂರ್ಣಾಂಕ sd, ರಚನೆ sockaddr *sa);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_CLOSEFROM
ಶೂನ್ಯ closefrom(ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_DECL_FTRUNCATE) && HAVE_DECL_FTRUNCATE == 0
ಪೂರ್ಣಾಂಕ ftruncate(ಪೂರ್ಣಾಂಕ filedes, off_t ಉದ್ದಳತೆ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GETLINE
#ಅನ್ತರ್ಭಾವ <stdio.h>
ssize_t getline(ಅಕ್ಷರ **, ಗಾತ್ರ_t *, FILE *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GETPAGESIZE
ಪೂರ್ಣಾಂಕ getpagesize(ಶೂನ್ಯ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GETCWD
ಅಕ್ಷರ *getcwd(ಅಕ್ಷರ *pt, ಗಾತ್ರ_t ಗಾತ್ರ_2);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GETEXECPATH
/* XXX this relies on correct fallback behaviour */
#ವ್ಯಾಖ್ಯಾನಿಸು getexecpath(a, b) (-1)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_KILLPG
ಪೂರ್ಣಾಂಕ killpg(pid_t, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_DECL_MEMMEM) && HAVE_DECL_MEMMEM == 0
ಶೂನ್ಯ *memmem(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *, ಗಾತ್ರ_t);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_REALLOCARRAY
ಶೂನ್ಯ *reallocarray(ಶೂನ್ಯ *, ಗಾತ್ರ_t, ಗಾತ್ರ_t);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_RECALLOCARRAY
ಶೂನ್ಯ *recallocarray(ಶೂನ್ಯ *, ಗಾತ್ರ_t, ಗಾತ್ರ_t, ಗಾತ್ರ_t);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_RRESVPORT_AF
ಪೂರ್ಣಾಂಕ rresvport_af(ಪೂರ್ಣಾಂಕ *alport, sa_family_t af);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRLCPY
ಗಾತ್ರ_t strlcpy(ಅಕ್ಷರ *dst, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಗಾತ್ರ_t siz);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRLCAT
ಗಾತ್ರ_t strlcat(ಅಕ್ಷರ *dst, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಗಾತ್ರ_t siz);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRCASESTR
ಅಕ್ಷರ *strcasestr(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRNLEN
ಗಾತ್ರ_t strnlen(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಗಾತ್ರ_t);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRNDUP
ಅಕ್ಷರ *strndup(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ಗಾತ್ರ_t n);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SETENV
ಪೂರ್ಣಾಂಕ setenv(ನೋಂದಣಿ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ನೋಂದಣಿ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮೌಲ್ಯ, ಪೂರ್ಣಾಂಕ rewrite);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRMODE
ಶೂನ್ಯ strmode(ಪೂರ್ಣಾಂಕ ಬಹುಲಕ, ಅಕ್ಷರ *p);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRPTIME
#ಅನ್ತರ್ಭಾವ  <time.h>
ಅಕ್ಷರ *strptime(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *buf, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ರಚನೆ tm *tm);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(HAVE_MKDTEMP)
ಪೂರ್ಣಾಂಕ mkstemps(ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ slen);
ಪೂರ್ಣಾಂಕ mkstemp(ಅಕ್ಷರ *ಮಾರ್ಗ);
ಅಕ್ಷರ *mkdtemp(ಅಕ್ಷರ *ಮಾರ್ಗ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು mkstemp(x) _ssh_mkstemp(x)
ಪೂರ್ಣಾಂಕ _ssh_mkstemp(ಅಕ್ಷರ *);

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_DAEMON
ಪೂರ್ಣಾಂಕ daemon(ಪೂರ್ಣಾಂಕ nochdir, ಪೂರ್ಣಾಂಕ noclose);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_DIRNAME
ಅಕ್ಷರ *dirname(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FMT_SCALED
#ವ್ಯಾಖ್ಯಾನಿಸು	FMT_SCALED_STRSIZE	7
ಪೂರ್ಣಾಂಕ	fmt_scaled(ದೀರ್ಘ ದೀರ್ಘ ಸಂಖ್ಯೆ, ಅಕ್ಷರ *ಫಲಿತಾಂಶ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ಪರಿಶೀಲನೆ_SCALED
ಪೂರ್ಣಾಂಕ	ಪರಿಶೀಲನೆ_scaled(ಅಕ್ಷರ *, ದೀರ್ಘ ದೀರ್ಘ *);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
ಅಕ್ಷರ *inet_ntoa(ರಚನೆ in_addr ಒಳ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_INET_NTOP
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *inet_ntop(ಪೂರ್ಣಾಂಕ af, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *src, ಅಕ್ಷರ *dst, socklen_t ಗಾತ್ರ_2);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_INET_ATON
ಪೂರ್ಣಾಂಕ inet_aton(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cp, ರಚನೆ in_addr *addr);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRSEP
ಅಕ್ಷರ *strsep(ಅಕ್ಷರ **stringp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *delim);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SETPROCTITLE
ಶೂನ್ಯ setproctitle(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...);
ಶೂನ್ಯ compat_init_setproctitle(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ *argv[]);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GETGROUPLIST
ಪೂರ್ಣಾಂಕ getgrouplist(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, gid_t, gid_t *, ಪೂರ್ಣಾಂಕ *);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
ಪೂರ್ಣಾಂಕ BSDgetopt(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *argv, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *opts) __THROW;
#ಅನ್ತರ್ಭಾವ "openbsd-compat/getopt.h"
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ ((defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0) || \
    (defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0))
# include <sys/types.h>
# include <sys/uio.h>

# ಆದರೆ defined(HAVE_DECL_READV) && HAVE_DECL_READV == 0
ಪೂರ್ಣಾಂಕ readv(ಪೂರ್ಣಾಂಕ, ರಚನೆ iovec *, ಪೂರ್ಣಾಂಕ);
# endif

# ಆದರೆ defined(HAVE_DECL_WRITEV) && HAVE_DECL_WRITEV == 0
ಪೂರ್ಣಾಂಕ writev(ಪೂರ್ಣಾಂಕ, ರಚನೆ iovec *, ಪೂರ್ಣಾಂಕ);
# endif
#ಆದರೆ_ಅಂತ್ಯ

/* Home grown routines */
#ಅನ್ತರ್ಭಾವ "bsd-signal.h"
#ಅನ್ತರ್ಭಾವ "bsd-misc.h"
#ಅನ್ತರ್ಭಾವ "bsd-setres_id.h"
#ಅನ್ತರ್ಭಾವ "bsd-statvfs.h"
#ಅನ್ತರ್ಭಾವ "bsd-waitpid.h"
#ಅನ್ತರ್ಭಾವ "bsd-poll.h"

#ಆದರೆ defined(HAVE_DECL_GETPEEREID) && HAVE_DECL_GETPEEREID == 0
ಪೂರ್ಣಾಂಕ getpeereid(ಪೂರ್ಣಾಂಕ , uid_t *, gid_t *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ARC4RANDOM
uint32_t arc4random(ಶೂನ್ಯ);
#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_ARC4RANDOM */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ARC4RANDOM_BUF
ಶೂನ್ಯ arc4random_buf(ಶೂನ್ಯ *, ಗಾತ್ರ_t);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ARC4RANDOM_STIR
# define arc4random_stir()
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ARC4_RANDOM_ಏಕರೂಪ
uint32_t arc4random_ಏಕರೂಪ(uint32_t);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ASPRINTF
ಪೂರ್ಣಾಂಕ asprintf(ಅಕ್ಷರ **, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_OPENPTY
# include <sys/ioctl.h>	/* for struct winsize */
ಪೂರ್ಣಾಂಕ openpty(ಪೂರ್ಣಾಂಕ *, ಪೂರ್ಣಾಂಕ *, ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ರಚನೆ termios *,
    ಸ್ಥಿರಾಂಕ ರಚನೆ winsize *);
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_OPENPTY */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SNPRINTF
ಪೂರ್ಣಾಂಕ snprintf(ಅಕ್ಷರ *, ಗಾತ್ರ_t, SNPRINTF_CONST ಅಕ್ಷರ *, ...);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRTOLL
ದೀರ್ಘ ದೀರ್ಘ strtoll(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ **, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRTOUL
ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ strtoul(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ **, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRTOULL
ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ strtoull(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ **, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRTONUM
ದೀರ್ಘ ದೀರ್ಘ strtonum(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ದೀರ್ಘ ದೀರ್ಘ, ದೀರ್ಘ ದೀರ್ಘ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **);
#ಆದರೆ_ಅಂತ್ಯ

/* multibyte character support */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_MBLEN
# define mblen(x, y)	(1)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_WCWIDTH
# define wcwidth(x)	(((x) >= 0x20 && (x) <= 0x7e) ? 1 : -1)
/* force our no-op nl_langinfo and mbtowc */
# undef HAVE_NL_LANGINFO
# undef HAVE_MBTOWC
# undef HAVE_LANGINFO_H
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_NL_LANGINFO
# define nl_langinfo(x)	""
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_MBTOWC
ಪೂರ್ಣಾಂಕ mbtowc(wchar_t *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ*, ಗಾತ್ರ_t);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(HAVE_VASPRINTF) || !defined(HAVE_VSNPRINTF)
# include <stdarg.h>
#ಆದರೆ_ಅಂತ್ಯ

/*
 * Some platforms unconditionally undefine va_copy() so we define VA_COPY()
 * instead.  This is known to be the case on at least some configurations of
 * AIX with the xlc compiler.
 */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ VA_COPY
# ifdef HAVE_VA_COPY
#  define VA_COPY(dest, src) va_copy(dest, src)
# ಇಲ್ಲದಿದ್ದರೆ
#  ifdef HAVE___VA_COPY
#   define VA_COPY(dest, src) __va_copy(dest, src)
#  ಇಲ್ಲದಿದ್ದರೆ
#   define VA_COPY(dest, src) (dest) = (src)
#  endif
# endif
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_VASPRINTF
ಪೂರ್ಣಾಂಕ vasprintf(ಅಕ್ಷರ **, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, va_list);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_VSNPRINTF
ಪೂರ್ಣಾಂಕ vsnprintf(ಅಕ್ಷರ *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, va_list);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_USER_FROM_UID
ಅಕ್ಷರ *user_from_uid(uid_t, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ಗುಂಪು_FROM_GID
ಅಕ್ಷರ *ಗುಂಪು_from_gid(gid_t, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_TIMINGSAFE_BCMP
ಪೂರ್ಣಾಂಕ timingsafe_bcmp(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *, ಗಾತ್ರ_t);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_BCRYPT_PBKDF
ಪೂರ್ಣಾಂಕ	bcrypt_pbkdf(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ uint8_t *, ಗಾತ್ರ_t,
    uint8_t *, ಗಾತ್ರ_t, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_EXPLICIT_BZERO
ಶೂನ್ಯ explicit_bzero(ಶೂನ್ಯ *p, ಗಾತ್ರ_t n);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FREEZERO
ಶೂನ್ಯ freezero(ಶೂನ್ಯ *, ಗಾತ್ರ_t);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_LOCALTIME_R
ರಚನೆ tm *localtime_r(ಸ್ಥಿರಾಂಕ time_t *, ರಚನೆ tm *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_TIMEGM
#ಅನ್ತರ್ಭಾವ <time.h>
time_t timegm(ರಚನೆ tm *);
#ಆದರೆ_ಅಂತ್ಯ

ಅಕ್ಷರ *xcrypt(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *password, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *salt);
ಅಕ್ಷರ *shadow_pw(ರಚನೆ passwd *pw);

/* rfc2553 socket API replacements */
#ಅನ್ತರ್ಭಾವ "fake-rfc2553.h"

/* Routines for a single OS platform */
#ಅನ್ತರ್ಭಾವ "bsd-cygwin_util.h"

#ಅನ್ತರ್ಭಾವ "port-aix.h"
#ಅನ್ತರ್ಭಾವ "port-irix.h"
#ಅನ್ತರ್ಭಾವ "port-linux.h"
#ಅನ್ತರ್ಭಾವ "port-solaris.h"
#ಅನ್ತರ್ಭಾವ "port-net.h"
#ಅನ್ತರ್ಭಾವ "port-uw.h"

/* _FORTIFY_SOURCE breaks FD_ISSET(n)/FD_SET(n) for n > FD_SETSIZE. Avoid. */
#ಆದರೆ defined(HAVE_FEATURES_H) && defined(FORTIFY_ಮೂಲ)
# include <features.h>
# ಆದರೆ defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  ಆದರೆ __GLIBC_PREREQ(2, 15) && (FORTIFY_ಮೂಲ > 0)
#   include <sys/socket.h>  /* Ensure include guard is defined */
#   undef FD_SET
#   undef FD_ISSET
#   define FD_SET(n, ಗಣ)	kludge_FD_ಗಣ(n, ಗಣ)
#   define FD_ISSET(n, ಗಣ)	kludge_FD_ISSET(n, ಗಣ)
ಶೂನ್ಯ kludge_FD_ಗಣ(ಪೂರ್ಣಾಂಕ, fd_set *);
ಪೂರ್ಣಾಂಕ kludge_FD_ISSET(ಪೂರ್ಣಾಂಕ, fd_set *);
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

#ಆದರೆ_ಅಂತ್ಯ /* _OPENBSD_COMPAT_H */
