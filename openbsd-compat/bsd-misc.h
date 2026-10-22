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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _BSD_MISC_H
#ವ್ಯಾಖ್ಯಾನಿಸು _BSD_MISC_H

#ಅನ್ತರ್ಭಾವ "includes.h"

ಅಕ್ಷರ *ssh_get_progname(ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ ಬೀಜ_from_prngd(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *, ಗಾತ್ರ_t);

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SETSID
#ವ್ಯಾಖ್ಯಾನಿಸು setsid() setpgrp(0, getpid())
#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_SETSID */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SETENV
ಪೂರ್ಣಾಂಕ setenv(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_SETENV */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SETLOGIN
ಪೂರ್ಣಾಂಕ setlogin(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_SETLOGIN */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_INNETGR
ಪೂರ್ಣಾಂಕ innetgr(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_INNETGR */

#ಆದರೆ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
ಪೂರ್ಣಾಂಕ seteuid(uid_t);
#ಆದರೆ_ಅಂತ್ಯ /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ಆದರೆ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
ಪೂರ್ಣಾಂಕ setegid(uid_t);
#ಆದರೆ_ಅಂತ್ಯ /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ಆದರೆ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *strerror(ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(HAVE_SETLINEBUF)
#ವ್ಯಾಖ್ಯಾನಿಸು setlinebuf(a)	(setvbuf((a), ಖಾಲಿ, _IOLBF, 0))
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_UTIMES
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRUCT_TIMEVAL
ರಚನೆ timeval {
	ದೀರ್ಘ tv_sec;
	ದೀರ್ಘ tv_usec;
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_STRUCT_TIMEVAL */

ಪೂರ್ಣಾಂಕ utimes(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ timeval *);
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_UTIMES */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_DIRFD
ಪೂರ್ಣಾಂಕ dirfd(ಶೂನ್ಯ *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ AT_FDCWD
# define AT_FDCWD (-2)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FCHMODAT
ಪೂರ್ಣಾಂಕ fchmodat(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಬಹುಲಕ_t, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FCHOWNAT
ಪೂರ್ಣಾಂಕ fchownat(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, uid_t, gid_t, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FSTATAT
ಪೂರ್ಣಾಂಕ fstatat(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ stat *, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_UNLINKAT
ಪೂರ್ಣಾಂಕ unlinkat(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_TRUNCATE
ಪೂರ್ಣಾಂಕ truncate (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, off_t);
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_TRUNCATE */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRUCT_TIMESPEC
ರಚನೆ timespec {
	time_t	tv_sec;
	ದೀರ್ಘ	tv_nsec;
};
#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_STRUCT_TIMESPEC */

#ಆದರೆ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
ಪೂರ್ಣಾಂಕ nanosleep(ಸ್ಥಿರಾಂಕ ರಚನೆ timespec *, ರಚನೆ timespec *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
ಪೂರ್ಣಾಂಕ utimensat(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ರಚನೆ timespec[2], ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_UTIMENSAT */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_USLEEP
ಪೂರ್ಣಾಂಕ usleep(ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ useconds);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_TCGETPGRP
pid_t tcgetpgrp(ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_TCSENDBREAK
ಪೂರ್ಣಾಂಕ tcsendbreak(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_UNSETENV
ಪೂರ್ಣಾಂಕ unsetenv(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ISBLANK
ಪೂರ್ಣಾಂಕ	isblank(ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GETPGID
pid_t getpgid(pid_t);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_PSELECT
ಪೂರ್ಣಾಂಕ pselect(ಪೂರ್ಣಾಂಕ, fd_set *, fd_set *, fd_set *, ಸ್ಥಿರಾಂಕ ರಚನೆ timespec *,
    ಸ್ಥಿರಾಂಕ sigset_t *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ENDGRENT
# define endgrent() ಮಾಡು { } ಆಗ(0)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_KRB5_GET_ERROR_ಸಂದೇಶ
# define krb5_get_error_ಸಂದೇಶ krb5_get_err_ಪಠ್ಯ
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_KRB5_FREE_ERROR_ಸಂದೇಶ
# define krb5_free_error_ಸಂದೇಶ(a,b) ಮಾಡು { } ಆಗ(0)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_PLEDGE
ಪೂರ್ಣಾಂಕ pledge(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *promises, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *execpromises);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_UNVEIL
ಪೂರ್ಣಾಂಕ unveil(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
#ಆದರೆ_ಅಂತ್ಯ

/* bsd-err.h */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ERR
ಶೂನ್ಯ err(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...) __attribute__((format(ಬರೆ, 2, 3)));
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ERRX
ಶೂನ್ಯ errx(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...) __attribute__((format(ಬರೆ, 2, 3)));
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_WARN
ಶೂನ್ಯ warn(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...) __attribute__((format(ಬರೆ, 1, 2)));
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_LLABS
ದೀರ್ಘ ದೀರ್ಘ llabs(ದೀರ್ಘ ದೀರ್ಘ);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
ಶೂನ್ಯ bzero(ಶೂನ್ಯ *, ಗಾತ್ರ_t);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_RAISE
ಪೂರ್ಣಾಂಕ ಎತ್ತು(ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GETSID
pid_t getsid(pid_t);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
ಪೂರ್ಣಾಂಕ flock(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_LOCALTIME_R
ರಚನೆ tm *localtime_r(ಸ್ಥಿರಾಂಕ time_t *, ರಚನೆ tm *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_CLOCK_GETTIME
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಪೂರ್ಣಾಂಕ clockid_t;
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ CLOCK_REALTIME
# define CLOCK_REALTIME	0
#ಆದರೆ_ಅಂತ್ಯ
ಪೂರ್ಣಾಂಕ clock_gettime(clockid_t, ರಚನೆ timespec *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_REALPATH
#ವ್ಯಾಖ್ಯಾನಿಸು realpath(x, y)	(sftp_realpath((x), (y)))
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ /* _BSD_MISC_H */
