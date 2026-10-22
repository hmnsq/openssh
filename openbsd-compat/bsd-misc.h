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

#اگر_غیر_تعریف_شدہ _BSD_MISC_H
#تعریف_کرو _BSD_MISC_H

#شامل "includes.h"

حرف *ssh_get_progname(حرف *);
صحیح بیج_from_prngd(غیرعلامتی حرف *, سائز_t);

#اگر_غیر_تعریف_شدہ HAVE_SETSID
#تعریف_کرو setsid() setpgrp(0, getpid())
#اگر_ختم /* !HAVE_SETSID */

#اگر_غیر_تعریف_شدہ HAVE_SETENV
صحیح setenv(ثابت حرف *, ثابت حرف *, صحیح);
#اگر_ختم /* !HAVE_SETENV */

#اگر_غیر_تعریف_شدہ HAVE_SETLOGIN
صحیح setlogin(ثابت حرف *);
#اگر_ختم /* !HAVE_SETLOGIN */

#اگر_غیر_تعریف_شدہ HAVE_INNETGR
صحیح innetgr(ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);
#اگر_ختم /* HAVE_INNETGR */

#اگر !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
صحیح seteuid(uid_t);
#اگر_ختم /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#اگر !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
صحیح setegid(uid_t);
#اگر_ختم /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#اگر !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ثابت حرف *strerror(صحیح);
#اگر_ختم

#اگر !defined(HAVE_SETLINEBUF)
#تعریف_کرو setlinebuf(a)	(setvbuf((a), تہی, _IOLBF, 0))
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_UTIMES
#اگر_غیر_تعریف_شدہ HAVE_STRUCT_TIMEVAL
ساخت timeval {
	طویل tv_sec;
	طویل tv_usec;
}
#اگر_ختم /* HAVE_STRUCT_TIMEVAL */

صحیح utimes(ثابت حرف *, ساخت timeval *);
#اگر_ختم /* HAVE_UTIMES */

#اگر_غیر_تعریف_شدہ HAVE_DIRFD
صحیح dirfd(خالی *);
#اگر_ختم

#اگر_غیر_تعریف_شدہ AT_FDCWD
# define AT_FDCWD (-2)
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_FCHMODAT
صحیح fchmodat(صحیح, ثابت حرف *, منوال_t, صحیح);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_FCHOWNAT
صحیح fchownat(صحیح, ثابت حرف *, uid_t, gid_t, صحیح);
#اگر_ختم

#اگر_تعریف_شدہ HAVE_FSTATAT
صحیح fstatat(صحیح, ثابت حرف *, ساخت stat *, صحیح);
#اگر_ختم

#اگر_تعریف_شدہ HAVE_UNLINKAT
صحیح unlinkat(صحیح, ثابت حرف *, صحیح);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_TRUNCATE
صحیح truncate (ثابت حرف *, off_t);
#اگر_ختم /* HAVE_TRUNCATE */

#اگر_غیر_تعریف_شدہ HAVE_STRUCT_TIMESPEC
ساخت timespec {
	time_t	tv_sec;
	طویل	tv_nsec;
};
#اگر_ختم /* !HAVE_STRUCT_TIMESPEC */

#اگر !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
صحیح nanosleep(ثابت ساخت timespec *, ساخت timespec *);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
صحیح utimensat(صحیح, ثابت حرف *, ثابت ساخت timespec[2], صحیح);
#اگر_ختم /* !HAVE_UTIMENSAT */

#اگر_غیر_تعریف_شدہ HAVE_USLEEP
صحیح usleep(غیرعلامتی صحیح useconds);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_TCGETPGRP
pid_t tcgetpgrp(صحیح);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_TCSENDBREAK
صحیح tcsendbreak(صحیح, صحیح);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_UNSETENV
صحیح unsetenv(ثابت حرف *);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_ISBLANK
صحیح	isblank(صحیح);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_GETPGID
pid_t getpgid(pid_t);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_PSELECT
صحیح pselect(صحیح, fd_set *, fd_set *, fd_set *, ثابت ساخت timespec *,
    ثابت sigset_t *);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_ENDGRENT
# define endgrent() کرو { } جب(0)
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_KRB5_GET_ERROR_پیغام
# define krb5_get_error_پیغام krb5_get_err_متن
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_KRB5_FREE_ERROR_پیغام
# define krb5_free_error_پیغام(a,b) کرو { } جب(0)
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_PLEDGE
صحیح pledge(ثابت حرف *promises, ثابت حرف *execpromises);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_UNVEIL
صحیح unveil(ثابت حرف *, ثابت حرف *);
#اگر_ختم

/* bsd-err.h */
#اگر_غیر_تعریف_شدہ HAVE_ERR
خالی err(صحیح, ثابت حرف *, ...) __attribute__((format(لکھو, 2, 3)));
#اگر_ختم
#اگر_غیر_تعریف_شدہ HAVE_ERRX
خالی errx(صحیح, ثابت حرف *, ...) __attribute__((format(لکھو, 2, 3)));
#اگر_ختم
#اگر_غیر_تعریف_شدہ HAVE_WARN
خالی warn(ثابت حرف *, ...) __attribute__((format(لکھو, 1, 2)));
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_LLABS
طویل طویل llabs(طویل طویل);
#اگر_ختم

#اگر defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
خالی bzero(خالی *, سائز_t);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_RAISE
صحیح اٹھاؤ(صحیح);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_GETSID
pid_t getsid(pid_t);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
صحیح flock(صحیح, صحیح);
#اگر_ختم

#اگر_تعریف_شدہ FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_LOCALTIME_R
ساخت tm *localtime_r(ثابت time_t *, ساخت tm *);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_CLOCK_GETTIME
قسمتعریف صحیح clockid_t;
#اگر_غیر_تعریف_شدہ CLOCK_REALTIME
# define CLOCK_REALTIME	0
#اگر_ختم
صحیح clock_gettime(clockid_t, ساخت timespec *);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_REALPATH
#تعریف_کرو realpath(x, y)	(sftp_realpath((x), (y)))
#اگر_ختم

#اگر_ختم /* _BSD_MISC_H */
