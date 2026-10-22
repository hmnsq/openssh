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

अक्षर *ssh_get_progname(अक्षर *);
पूर्णांक seed_from_prngd(अचिन्हित अक्षर *, माप_प्रकार);

#ifndef HAVE_SETSID
#define setsid() setpgrp(0, getpid())
#endif /* !HAVE_SETSID */

#ifndef HAVE_SETENV
पूर्णांक setenv(स्थिरांक अक्षर *, स्थिरांक अक्षर *, पूर्णांक);
#endif /* !HAVE_SETENV */

#ifndef HAVE_SETLOGIN
पूर्णांक setlogin(स्थिरांक अक्षर *);
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
पूर्णांक innetgr(स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *);
#endif /* HAVE_INNETGR */

#जर !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
पूर्णांक seteuid(uid_t);
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#जर !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
पूर्णांक setegid(uid_t);
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#जर !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
स्थिरांक अक्षर *म_त्रुटि(पूर्णांक);
#endif

#जर !defined(HAVE_SETLINEBUF)
#define setlinebuf(a)	(रखो_भबफ((a), रिक्त, _IOLBF, 0))
#endif

#ifndef HAVE_UTIMES
#ifndef HAVE_STRUCT_TIMEVAL
संरचना timeval {
	दीर्घ tv_sec;
	दीर्घ tv_usec;
}
#endif /* HAVE_STRUCT_TIMEVAL */

पूर्णांक utimes(स्थिरांक अक्षर *, संरचना timeval *);
#endif /* HAVE_UTIMES */

#ifndef HAVE_DIRFD
पूर्णांक dirfd(शून्य *);
#endif

#ifndef AT_FDCWD
# define AT_FDCWD (-2)
#endif

#ifndef HAVE_FCHMODAT
पूर्णांक fchmodat(पूर्णांक, स्थिरांक अक्षर *, mode_t, पूर्णांक);
#endif

#ifndef HAVE_FCHOWNAT
पूर्णांक fchownat(पूर्णांक, स्थिरांक अक्षर *, uid_t, gid_t, पूर्णांक);
#endif

#ifdef HAVE_FSTATAT
पूर्णांक fstatat(पूर्णांक, स्थिरांक अक्षर *, संरचना stat *, पूर्णांक);
#endif

#ifdef HAVE_UNLINKAT
पूर्णांक unlinkat(पूर्णांक, स्थिरांक अक्षर *, पूर्णांक);
#endif

#ifndef HAVE_TRUNCATE
पूर्णांक truncate (स्थिरांक अक्षर *, off_t);
#endif /* HAVE_TRUNCATE */

#ifndef HAVE_STRUCT_TIMESPEC
संरचना timespec {
	समय_प्रकार	tv_sec;
	दीर्घ	tv_nsec;
};
#endif /* !HAVE_STRUCT_TIMESPEC */

#जर !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
पूर्णांक nanosleep(स्थिरांक संरचना timespec *, संरचना timespec *);
#endif

#ifndef HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
पूर्णांक utimensat(पूर्णांक, स्थिरांक अक्षर *, स्थिरांक संरचना timespec[2], पूर्णांक);
#endif /* !HAVE_UTIMENSAT */

#ifndef HAVE_USLEEP
पूर्णांक usleep(अचिन्हित पूर्णांक useconds);
#endif

#ifndef HAVE_TCGETPGRP
pid_t tcgetpgrp(पूर्णांक);
#endif

#ifndef HAVE_TCSENDBREAK
पूर्णांक tcsendbreak(पूर्णांक, पूर्णांक);
#endif

#ifndef HAVE_UNSETENV
पूर्णांक unsetenv(स्थिरांक अक्षर *);
#endif

#ifndef HAVE_ISBLANK
पूर्णांक	isblank(पूर्णांक);
#endif

#ifndef HAVE_GETPGID
pid_t getpgid(pid_t);
#endif

#ifndef HAVE_PSELECT
पूर्णांक pselect(पूर्णांक, fd_set *, fd_set *, fd_set *, स्थिरांक संरचना timespec *,
    स्थिरांक sigset_t *);
#endif

#ifndef HAVE_ENDGRENT
# define endgrent() करा { } पर्यंत(0)
#endif

#ifndef HAVE_KRB5_GET_ERROR_MESSAGE
# define krb5_get_error_message krb5_get_err_text
#endif

#ifndef HAVE_KRB5_FREE_ERROR_MESSAGE
# define krb5_free_error_message(a,b) करा { } पर्यंत(0)
#endif

#ifndef HAVE_PLEDGE
पूर्णांक pledge(स्थिरांक अक्षर *promises, स्थिरांक अक्षर *execpromises);
#endif

#ifndef HAVE_UNVEIL
पूर्णांक unveil(स्थिरांक अक्षर *, स्थिरांक अक्षर *);
#endif

/* bsd-err.h */
#ifndef HAVE_ERR
शून्य err(पूर्णांक, स्थिरांक अक्षर *, ...) __attribute__((format(म_लिखो, 2, 3)));
#endif
#ifndef HAVE_ERRX
शून्य errx(पूर्णांक, स्थिरांक अक्षर *, ...) __attribute__((format(म_लिखो, 2, 3)));
#endif
#ifndef HAVE_WARN
शून्य warn(स्थिरांक अक्षर *, ...) __attribute__((format(म_लिखो, 1, 2)));
#endif

#ifndef HAVE_LLABS
दीर्घ दीर्घ llabs(दीर्घ दीर्घ);
#endif

#जर defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
शून्य bzero(शून्य *, माप_प्रकार);
#endif

#ifndef HAVE_RAISE
पूर्णांक उठवा(पूर्णांक);
#endif

#ifndef HAVE_GETSID
pid_t getsid(pid_t);
#endif

#ifndef HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
पूर्णांक flock(पूर्णांक, पूर्णांक);
#endif

#ifdef FFLUSH_NULL_BUG
# define ख_साफ(x)	(_ssh_compat_fflush(x))
#endif

#ifndef HAVE_LOCALTIME_R
संरचना पंचांग *localtime_r(स्थिरांक समय_प्रकार *, संरचना पंचांग *);
#endif

#ifndef HAVE_CLOCK_GETTIME
प्रकारव्याख्या पूर्णांक clockid_t;
#ifndef CLOCK_REALTIME
# define CLOCK_REALTIME	0
#endif
पूर्णांक clock_gettime(clockid_t, संरचना timespec *);
#endif

#ifndef HAVE_REALPATH
#define realpath(x, y)	(sftp_realpath((x), (y)))
#endif

#endif /* _BSD_MISC_H */
