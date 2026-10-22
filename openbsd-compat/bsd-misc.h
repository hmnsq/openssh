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

#ಅನ್ತರ್ಭಾವ "includes.h"

ವರ್ಣ *ssh_get_progname(ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ seed_from_prngd(unsigned ವರ್ಣ *, size_t);

#ifndef HAVE_SETSID
#define setsid() setpgrp(0, getpid())
#endif /* !HAVE_SETSID */

#ifndef HAVE_SETENV
ಪೂರ್ಣಾಙ್ಕ setenv(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
#endif /* !HAVE_SETENV */

#ifndef HAVE_SETLOGIN
ಪೂರ್ಣಾಙ್ಕ setlogin(ಧ್ರುವ ವರ್ಣ *);
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
ಪೂರ್ಣಾಙ್ಕ innetgr(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
#endif /* HAVE_INNETGR */

#ಯದಿ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
ಪೂರ್ಣಾಙ್ಕ seteuid(uid_t);
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ಯದಿ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
ಪೂರ್ಣಾಙ್ಕ setegid(uid_t);
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ಯದಿ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ಧ್ರುವ ವರ್ಣ *strerror(ಪೂರ್ಣಾಙ್ಕ);
#endif

#ಯದಿ !defined(HAVE_SETLINEBUF)
#define setlinebuf(a)	(setvbuf((a), ರಿಕ್ತ, _IOLBF, 0))
#endif

#ifndef HAVE_UTIMES
#ifndef HAVE_STRUCT_TIMEVAL
ಸಂರಚನಾ timeval {
	long tv_sec;
	long tv_usec;
}
#endif /* HAVE_STRUCT_TIMEVAL */

ಪೂರ್ಣಾಙ್ಕ utimes(ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ timeval *);
#endif /* HAVE_UTIMES */

#ifndef HAVE_DIRFD
ಪೂರ್ಣಾಙ್ಕ dirfd(ಶೂನ್ಯ *);
#endif

#ifndef AT_FDCWD
# define AT_FDCWD (-2)
#endif

#ifndef HAVE_FCHMODAT
ಪೂರ್ಣಾಙ್ಕ fchmodat(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, mode_t, ಪೂರ್ಣಾಙ್ಕ);
#endif

#ifndef HAVE_FCHOWNAT
ಪೂರ್ಣಾಙ್ಕ fchownat(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, uid_t, gid_t, ಪೂರ್ಣಾಙ್ಕ);
#endif

#ifdef HAVE_FSTATAT
ಪೂರ್ಣಾಙ್ಕ fstatat(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ stat *, ಪೂರ್ಣಾಙ್ಕ);
#endif

#ifdef HAVE_UNLINKAT
ಪೂರ್ಣಾಙ್ಕ unlinkat(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
#endif

#ifndef HAVE_TRUNCATE
ಪೂರ್ಣಾಙ್ಕ truncate (ಧ್ರುವ ವರ್ಣ *, off_t);
#endif /* HAVE_TRUNCATE */

#ifndef HAVE_STRUCT_TIMESPEC
ಸಂರಚನಾ timespec {
	time_t	tv_sec;
	long	tv_nsec;
};
#endif /* !HAVE_STRUCT_TIMESPEC */

#ಯದಿ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
ಪೂರ್ಣಾಙ್ಕ nanosleep(ಧ್ರುವ ಸಂರಚನಾ timespec *, ಸಂರಚನಾ timespec *);
#endif

#ifndef HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
ಪೂರ್ಣಾಙ್ಕ utimensat(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ಸಂರಚನಾ timespec[2], ಪೂರ್ಣಾಙ್ಕ);
#endif /* !HAVE_UTIMENSAT */

#ifndef HAVE_USLEEP
ಪೂರ್ಣಾಙ್ಕ usleep(unsigned ಪೂರ್ಣಾಙ್ಕ useconds);
#endif

#ifndef HAVE_TCGETPGRP
pid_t tcgetpgrp(ಪೂರ್ಣಾಙ್ಕ);
#endif

#ifndef HAVE_TCSENDBREAK
ಪೂರ್ಣಾಙ್ಕ tcsendbreak(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
#endif

#ifndef HAVE_UNSETENV
ಪೂರ್ಣಾಙ್ಕ unsetenv(ಧ್ರುವ ವರ್ಣ *);
#endif

#ifndef HAVE_ISBLANK
ಪೂರ್ಣಾಙ್ಕ	isblank(ಪೂರ್ಣಾಙ್ಕ);
#endif

#ifndef HAVE_GETPGID
pid_t getpgid(pid_t);
#endif

#ifndef HAVE_PSELECT
ಪೂರ್ಣಾಙ್ಕ pselect(ಪೂರ್ಣಾಙ್ಕ, fd_set *, fd_set *, fd_set *, ಧ್ರುವ ಸಂರಚನಾ timespec *,
    ಧ್ರುವ sigset_t *);
#endif

#ifndef HAVE_ENDGRENT
# define endgrent() ಕುರು { } ಯಾವತ್(0)
#endif

#ifndef HAVE_KRB5_GET_ERROR_MESSAGE
# define krb5_get_error_message krb5_get_err_text
#endif

#ifndef HAVE_KRB5_FREE_ERROR_MESSAGE
# define krb5_free_error_message(a,b) ಕುರು { } ಯಾವತ್(0)
#endif

#ifndef HAVE_PLEDGE
ಪೂರ್ಣಾಙ್ಕ pledge(ಧ್ರುವ ವರ್ಣ *promises, ಧ್ರುವ ವರ್ಣ *execpromises);
#endif

#ifndef HAVE_UNVEIL
ಪೂರ್ಣಾಙ್ಕ unveil(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
#endif

/* bsd-err.h */
#ifndef HAVE_ERR
ಶೂನ್ಯ err(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_ERRX
ಶೂನ್ಯ errx(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_WARN
ಶೂನ್ಯ warn(ಧ್ರುವ ವರ್ಣ *, ...) __attribute__((format(printf, 1, 2)));
#endif

#ifndef HAVE_LLABS
long long llabs(long long);
#endif

#ಯದಿ defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
ಶೂನ್ಯ bzero(ಶೂನ್ಯ *, size_t);
#endif

#ifndef HAVE_RAISE
ಪೂರ್ಣಾಙ್ಕ ಉತ್ಥಾಪಯ(ಪೂರ್ಣಾಙ್ಕ);
#endif

#ifndef HAVE_GETSID
pid_t getsid(pid_t);
#endif

#ifndef HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
ಪೂರ್ಣಾಙ್ಕ flock(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
#endif

#ifdef FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#endif

#ifndef HAVE_LOCALTIME_R
ಸಂರಚನಾ tm *localtime_r(ಧ್ರುವ time_t *, ಸಂರಚನಾ tm *);
#endif

#ifndef HAVE_CLOCK_GETTIME
ಪ್ರಕಾರನಿರ್ದೇಶ ಪೂರ್ಣಾಙ್ಕ clockid_t;
#ifndef CLOCK_REALTIME
# define CLOCK_REALTIME	0
#endif
ಪೂರ್ಣಾಙ್ಕ clock_gettime(clockid_t, ಸಂರಚನಾ timespec *);
#endif

#ifndef HAVE_REALPATH
#define realpath(x, y)	(sftp_realpath((x), (y)))
#endif

#endif /* _BSD_MISC_H */
