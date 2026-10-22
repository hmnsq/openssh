/*
 * Copyright (c) 1999-2004 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _BSD_MISC_H
#define _BSD_MISC_H

#अन्तर्भाव "includes.h"

वर्ण *ssh_get_progname(वर्ण *);
पूर्णाङ्क seed_from_prngd(अचिन्हित वर्ण *, माप_प्रकार);

#ifndef HAVE_SETSID
#define setsid() setpgrp(0, getpid())
#endif /* !HAVE_SETSID */

#ifndef HAVE_SETENV
पूर्णाङ्क setenv(ध्रुव वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क);
#endif /* !HAVE_SETENV */

#ifndef HAVE_SETLOGIN
पूर्णाङ्क setlogin(ध्रुव वर्ण *);
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
पूर्णाङ्क innetgr(ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *);
#endif /* HAVE_INNETGR */

#यदि !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
पूर्णाङ्क seteuid(uid_t);
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#यदि !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
पूर्णाङ्क setegid(uid_t);
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#यदि !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ध्रुव वर्ण *म_त्रुटि(पूर्णाङ्क);
#endif

#यदि !defined(HAVE_SETLINEBUF)
#define setlinebuf(a)	(रखो_भबफ((a), रिक्त, _IOLBF, 0))
#endif

#ifndef HAVE_UTIMES
#ifndef HAVE_STRUCT_TIMEVAL
संरचना timeval {
	दीर्घ tv_sec;
	दीर्घ tv_usec;
}
#endif /* HAVE_STRUCT_TIMEVAL */

पूर्णाङ्क utimes(ध्रुव वर्ण *, संरचना timeval *);
#endif /* HAVE_UTIMES */

#ifndef HAVE_DIRFD
पूर्णाङ्क dirfd(शून्य *);
#endif

#ifndef AT_FDCWD
# define AT_FDCWD (-2)
#endif

#ifndef HAVE_FCHMODAT
पूर्णाङ्क fchmodat(पूर्णाङ्क, ध्रुव वर्ण *, mode_t, पूर्णाङ्क);
#endif

#ifndef HAVE_FCHOWNAT
पूर्णाङ्क fchownat(पूर्णाङ्क, ध्रुव वर्ण *, uid_t, gid_t, पूर्णाङ्क);
#endif

#ifdef HAVE_FSTATAT
पूर्णाङ्क fstatat(पूर्णाङ्क, ध्रुव वर्ण *, संरचना stat *, पूर्णाङ्क);
#endif

#ifdef HAVE_UNLINKAT
पूर्णाङ्क unlinkat(पूर्णाङ्क, ध्रुव वर्ण *, पूर्णाङ्क);
#endif

#ifndef HAVE_TRUNCATE
पूर्णाङ्क truncate (ध्रुव वर्ण *, off_t);
#endif /* HAVE_TRUNCATE */

#ifndef HAVE_STRUCT_TIMESPEC
संरचना timespec {
	समय_प्रकार	tv_sec;
	दीर्घ	tv_nsec;
};
#endif /* !HAVE_STRUCT_TIMESPEC */

#यदि !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
पूर्णाङ्क nanosleep(ध्रुव संरचना timespec *, संरचना timespec *);
#endif

#ifndef HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
पूर्णाङ्क utimensat(पूर्णाङ्क, ध्रुव वर्ण *, ध्रुव संरचना timespec[2], पूर्णाङ्क);
#endif /* !HAVE_UTIMENSAT */

#ifndef HAVE_USLEEP
पूर्णाङ्क usleep(अचिन्हित पूर्णाङ्क useconds);
#endif

#ifndef HAVE_TCGETPGRP
pid_t tcgetpgrp(पूर्णाङ्क);
#endif

#ifndef HAVE_TCSENDBREAK
पूर्णाङ्क tcsendbreak(पूर्णाङ्क, पूर्णाङ्क);
#endif

#ifndef HAVE_UNSETENV
पूर्णाङ्क unsetenv(ध्रुव वर्ण *);
#endif

#ifndef HAVE_ISBLANK
पूर्णाङ्क	isblank(पूर्णाङ्क);
#endif

#ifndef HAVE_GETPGID
pid_t getpgid(pid_t);
#endif

#ifndef HAVE_PSELECT
पूर्णाङ्क pselect(पूर्णाङ्क, fd_set *, fd_set *, fd_set *, ध्रुव संरचना timespec *,
    ध्रुव sigset_t *);
#endif

#ifndef HAVE_ENDGRENT
# define endgrent() कुरु { } यावत्(0)
#endif

#ifndef HAVE_KRB5_GET_ERROR_MESSAGE
# define krb5_get_error_message krb5_get_err_text
#endif

#ifndef HAVE_KRB5_FREE_ERROR_MESSAGE
# define krb5_free_error_message(a,b) कुरु { } यावत्(0)
#endif

#ifndef HAVE_PLEDGE
पूर्णाङ्क pledge(ध्रुव वर्ण *promises, ध्रुव वर्ण *execpromises);
#endif

#ifndef HAVE_UNVEIL
पूर्णाङ्क unveil(ध्रुव वर्ण *, ध्रुव वर्ण *);
#endif

/* bsd-err.h */
#ifndef HAVE_ERR
शून्य err(पूर्णाङ्क, ध्रुव वर्ण *, ...) __attribute__((format(म_लिखो, 2, 3)));
#endif
#ifndef HAVE_ERRX
शून्य errx(पूर्णाङ्क, ध्रुव वर्ण *, ...) __attribute__((format(म_लिखो, 2, 3)));
#endif
#ifndef HAVE_WARN
शून्य warn(ध्रुव वर्ण *, ...) __attribute__((format(म_लिखो, 1, 2)));
#endif

#ifndef HAVE_LLABS
दीर्घ दीर्घ llabs(दीर्घ दीर्घ);
#endif

#यदि defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
शून्य bzero(शून्य *, माप_प्रकार);
#endif

#ifndef HAVE_RAISE
पूर्णाङ्क उत्थापय(पूर्णाङ्क);
#endif

#ifndef HAVE_GETSID
pid_t getsid(pid_t);
#endif

#ifndef HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
पूर्णाङ्क flock(पूर्णाङ्क, पूर्णाङ्क);
#endif

#ifdef FFLUSH_NULL_BUG
# define ख_साफ(x)	(_ssh_compat_fflush(x))
#endif

#ifndef HAVE_LOCALTIME_R
संरचना पंचांग *localtime_r(ध्रुव समय_प्रकार *, संरचना पंचांग *);
#endif

#ifndef HAVE_CLOCK_GETTIME
प्रकारनिर्देश पूर्णाङ्क clockid_t;
#ifndef CLOCK_REALTIME
# define CLOCK_REALTIME	0
#endif
पूर्णाङ्क clock_gettime(clockid_t, संरचना timespec *);
#endif

#ifndef HAVE_REALPATH
#define realpath(x, y)	(sftp_realpath((x), (y)))
#endif

#endif /* _BSD_MISC_H */
