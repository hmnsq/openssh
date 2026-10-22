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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _BSD_MISC_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _BSD_MISC_H

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

ਅੱਖਰ *ssh_get_progname(ਅੱਖਰ *);
ਪੂਰਨ ਬੀਜ_from_prngd(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *, ਮਾਪ_t);

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SETSID
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ setsid() setpgrp(0, getpid())
#ਜੇ_ਅੰਤ /* !HAVE_SETSID */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SETENV
ਪੂਰਨ setenv(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);
#ਜੇ_ਅੰਤ /* !HAVE_SETENV */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SETLOGIN
ਪੂਰਨ setlogin(ਅਚਲ ਅੱਖਰ *);
#ਜੇ_ਅੰਤ /* !HAVE_SETLOGIN */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_INNETGR
ਪੂਰਨ innetgr(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
#ਜੇ_ਅੰਤ /* HAVE_INNETGR */

#ਜੇ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
ਪੂਰਨ seteuid(uid_t);
#ਜੇ_ਅੰਤ /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ਜੇ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
ਪੂਰਨ setegid(uid_t);
#ਜੇ_ਅੰਤ /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ਜੇ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ਅਚਲ ਅੱਖਰ *strerror(ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ !defined(HAVE_SETLINEBUF)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ setlinebuf(a)	(setvbuf((a), ਨਿਰਾ, _IOLBF, 0))
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_UTIMES
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_TIMEVAL
ਬਣਤਰ timeval {
	ਲੰਮਾ tv_sec;
	ਲੰਮਾ tv_usec;
}
#ਜੇ_ਅੰਤ /* HAVE_STRUCT_TIMEVAL */

ਪੂਰਨ utimes(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ timeval *);
#ਜੇ_ਅੰਤ /* HAVE_UTIMES */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_DIRFD
ਪੂਰਨ dirfd(ਖਾਲੀ *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ AT_FDCWD
# define AT_FDCWD (-2)
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FCHMODAT
ਪੂਰਨ fchmodat(ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ਬਹੁਲਕ_t, ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FCHOWNAT
ਪੂਰਨ fchownat(ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, uid_t, gid_t, ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_FSTATAT
ਪੂਰਨ fstatat(ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ stat *, ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_UNLINKAT
ਪੂਰਨ unlinkat(ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_TRUNCATE
ਪੂਰਨ truncate (ਅਚਲ ਅੱਖਰ *, off_t);
#ਜੇ_ਅੰਤ /* HAVE_TRUNCATE */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_TIMESPEC
ਬਣਤਰ timespec {
	time_t	tv_sec;
	ਲੰਮਾ	tv_nsec;
};
#ਜੇ_ਅੰਤ /* !HAVE_STRUCT_TIMESPEC */

#ਜੇ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
ਪੂਰਨ nanosleep(ਅਚਲ ਬਣਤਰ timespec *, ਬਣਤਰ timespec *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
ਪੂਰਨ utimensat(ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਬਣਤਰ timespec[2], ਪੂਰਨ);
#ਜੇ_ਅੰਤ /* !HAVE_UTIMENSAT */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_USLEEP
ਪੂਰਨ usleep(ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ useconds);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_TCGETPGRP
pid_t tcgetpgrp(ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_TCSENDBREAK
ਪੂਰਨ tcsendbreak(ਪੂਰਨ, ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_UNSETENV
ਪੂਰਨ unsetenv(ਅਚਲ ਅੱਖਰ *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ISBLANK
ਪੂਰਨ	isblank(ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETPGID
pid_t getpgid(pid_t);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_PSELECT
ਪੂਰਨ pselect(ਪੂਰਨ, fd_set *, fd_set *, fd_set *, ਅਚਲ ਬਣਤਰ timespec *,
    ਅਚਲ sigset_t *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ENDGRENT
# define endgrent() ਕਰੋ { } ਜਦੋਂ(0)
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_KRB5_GET_ERROR_ਸੁਨੇਹਾ
# define krb5_get_error_ਸੁਨੇਹਾ krb5_get_err_ਪਾਠ
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_KRB5_FREE_ERROR_ਸੁਨੇਹਾ
# define krb5_free_error_ਸੁਨੇਹਾ(a,b) ਕਰੋ { } ਜਦੋਂ(0)
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_PLEDGE
ਪੂਰਨ pledge(ਅਚਲ ਅੱਖਰ *promises, ਅਚਲ ਅੱਖਰ *execpromises);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_UNVEIL
ਪੂਰਨ unveil(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
#ਜੇ_ਅੰਤ

/* bsd-err.h */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ERR
ਖਾਲੀ err(ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ...) __attribute__((format(ਲਿਖੋ, 2, 3)));
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ERRX
ਖਾਲੀ errx(ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ...) __attribute__((format(ਲਿਖੋ, 2, 3)));
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_WARN
ਖਾਲੀ warn(ਅਚਲ ਅੱਖਰ *, ...) __attribute__((format(ਲਿਖੋ, 1, 2)));
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_LLABS
ਲੰਮਾ ਲੰਮਾ llabs(ਲੰਮਾ ਲੰਮਾ);
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
ਖਾਲੀ bzero(ਖਾਲੀ *, ਮਾਪ_t);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_RAISE
ਪੂਰਨ ਉਠਾਓ(ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETSID
pid_t getsid(pid_t);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
ਪੂਰਨ flock(ਪੂਰਨ, ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_LOCALTIME_R
ਬਣਤਰ tm *localtime_r(ਅਚਲ time_t *, ਬਣਤਰ tm *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_CLOCK_GETTIME
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਪੂਰਨ clockid_t;
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ CLOCK_REALTIME
# define CLOCK_REALTIME	0
#ਜੇ_ਅੰਤ
ਪੂਰਨ clock_gettime(clockid_t, ਬਣਤਰ timespec *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_REALPATH
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ realpath(x, y)	(sftp_realpath((x), (y)))
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ /* _BSD_MISC_H */
