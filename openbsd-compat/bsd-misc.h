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

#यदि_अपरिभाषितम् _BSD_MISC_H
#परिभाषय _BSD_MISC_H

#अन्तर्भाव "includes.h"

वर्ण *ssh_get_progname(वर्ण *);
पूर्णाङ्क बीजम्_from_prngd(अचिह्नित वर्ण *, आकार_t);

#यदि_अपरिभाषितम् HAVE_SETSID
#परिभाषय setsid() setpgrp(0, getpid())
#यदि_अन्तः /* !HAVE_SETSID */

#यदि_अपरिभाषितम् HAVE_SETENV
पूर्णाङ्क setenv(ध्रुव वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क);
#यदि_अन्तः /* !HAVE_SETENV */

#यदि_अपरिभाषितम् HAVE_SETLOGIN
पूर्णाङ्क setlogin(ध्रुव वर्ण *);
#यदि_अन्तः /* !HAVE_SETLOGIN */

#यदि_अपरिभाषितम् HAVE_INNETGR
पूर्णाङ्क innetgr(ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *);
#यदि_अन्तः /* HAVE_INNETGR */

#यदि !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
पूर्णाङ्क seteuid(uid_t);
#यदि_अन्तः /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#यदि !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
पूर्णाङ्क setegid(uid_t);
#यदि_अन्तः /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#यदि !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ध्रुव वर्ण *strerror(पूर्णाङ्क);
#यदि_अन्तः

#यदि !defined(HAVE_SETLINEBUF)
#परिभाषय setlinebuf(a)	(setvbuf((a), रिक्त, _IOLBF, 0))
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_UTIMES
#यदि_अपरिभाषितम् HAVE_STRUCT_TIMEVAL
संरचना timeval {
	दीर्घ tv_sec;
	दीर्घ tv_usec;
}
#यदि_अन्तः /* HAVE_STRUCT_TIMEVAL */

पूर्णाङ्क utimes(ध्रुव वर्ण *, संरचना timeval *);
#यदि_अन्तः /* HAVE_UTIMES */

#यदि_अपरिभाषितम् HAVE_DIRFD
पूर्णाङ्क dirfd(शून्य *);
#यदि_अन्तः

#यदि_अपरिभाषितम् AT_FDCWD
# define AT_FDCWD (-2)
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_FCHMODAT
पूर्णाङ्क fchmodat(पूर्णाङ्क, ध्रुव वर्ण *, बहुलकम्_t, पूर्णाङ्क);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_FCHOWNAT
पूर्णाङ्क fchownat(पूर्णाङ्क, ध्रुव वर्ण *, uid_t, gid_t, पूर्णाङ्क);
#यदि_अन्तः

#यदि_परिभाषितम् HAVE_FSTATAT
पूर्णाङ्क fstatat(पूर्णाङ्क, ध्रुव वर्ण *, संरचना stat *, पूर्णाङ्क);
#यदि_अन्तः

#यदि_परिभाषितम् HAVE_UNLINKAT
पूर्णाङ्क unlinkat(पूर्णाङ्क, ध्रुव वर्ण *, पूर्णाङ्क);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_TRUNCATE
पूर्णाङ्क truncate (ध्रुव वर्ण *, off_t);
#यदि_अन्तः /* HAVE_TRUNCATE */

#यदि_अपरिभाषितम् HAVE_STRUCT_TIMESPEC
संरचना timespec {
	time_t	tv_sec;
	दीर्घ	tv_nsec;
};
#यदि_अन्तः /* !HAVE_STRUCT_TIMESPEC */

#यदि !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
पूर्णाङ्क nanosleep(ध्रुव संरचना timespec *, संरचना timespec *);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
पूर्णाङ्क utimensat(पूर्णाङ्क, ध्रुव वर्ण *, ध्रुव संरचना timespec[2], पूर्णाङ्क);
#यदि_अन्तः /* !HAVE_UTIMENSAT */

#यदि_अपरिभाषितम् HAVE_USLEEP
पूर्णाङ्क usleep(अचिह्नित पूर्णाङ्क useconds);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_TCGETPGRP
pid_t tcgetpgrp(पूर्णाङ्क);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_TCSENDBREAK
पूर्णाङ्क tcsendbreak(पूर्णाङ्क, पूर्णाङ्क);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_UNSETENV
पूर्णाङ्क unsetenv(ध्रुव वर्ण *);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_ISBLANK
पूर्णाङ्क	isblank(पूर्णाङ्क);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_GETPGID
pid_t getpgid(pid_t);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_PSELECT
पूर्णाङ्क pselect(पूर्णाङ्क, fd_set *, fd_set *, fd_set *, ध्रुव संरचना timespec *,
    ध्रुव sigset_t *);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_ENDGRENT
# define endgrent() कुरु { } यावत्(0)
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_KRB5_GET_ERROR_सन्देशः
# define krb5_get_error_सन्देशः krb5_get_err_text
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_KRB5_FREE_ERROR_सन्देशः
# define krb5_free_error_सन्देशः(a,b) कुरु { } यावत्(0)
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_PLEDGE
पूर्णाङ्क pledge(ध्रुव वर्ण *promises, ध्रुव वर्ण *execpromises);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_UNVEIL
पूर्णाङ्क unveil(ध्रुव वर्ण *, ध्रुव वर्ण *);
#यदि_अन्तः

/* bsd-err.h */
#यदि_अपरिभाषितम् HAVE_ERR
शून्य err(पूर्णाङ्क, ध्रुव वर्ण *, ...) __attribute__((format(प्रारूप_लिख, 2, 3)));
#यदि_अन्तः
#यदि_अपरिभाषितम् HAVE_ERRX
शून्य errx(पूर्णाङ्क, ध्रुव वर्ण *, ...) __attribute__((format(प्रारूप_लिख, 2, 3)));
#यदि_अन्तः
#यदि_अपरिभाषितम् HAVE_WARN
शून्य warn(ध्रुव वर्ण *, ...) __attribute__((format(प्रारूप_लिख, 1, 2)));
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_LLABS
दीर्घ दीर्घ llabs(दीर्घ दीर्घ);
#यदि_अन्तः

#यदि defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
शून्य bzero(शून्य *, आकार_t);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_RAISE
पूर्णाङ्क उत्थापय(पूर्णाङ्क);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_GETSID
pid_t getsid(pid_t);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
पूर्णाङ्क flock(पूर्णाङ्क, पूर्णाङ्क);
#यदि_अन्तः

#यदि_परिभाषितम् FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_LOCALTIME_R
संरचना tm *localtime_r(ध्रुव time_t *, संरचना tm *);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_CLOCK_GETTIME
प्रकारनिर्देश पूर्णाङ्क clockid_t;
#यदि_अपरिभाषितम् CLOCK_REALTIME
# define CLOCK_REALTIME	0
#यदि_अन्तः
पूर्णाङ्क clock_gettime(clockid_t, संरचना timespec *);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_REALPATH
#परिभाषय realpath(x, y)	(sftp_realpath((x), (y)))
#यदि_अन्तः

#यदि_अन्तः /* _BSD_MISC_H */
