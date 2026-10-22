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

#اگر_تعریف_نشده _BSD_MISC_H
#تعریف_کن _BSD_MISC_H

#ضمن "includes.h"

حرف *ssh_get_progname(حرف *);
صحيح دانه_from_prngd(بیعلامت حرف *, اندازه_t);

#اگر_تعریف_نشده HAVE_SETSID
#تعریف_کن setsid() setpgrp(0, getpid())
#پایان_اگر /* !HAVE_SETSID */

#اگر_تعریف_نشده HAVE_SETENV
صحيح setenv(ثابت حرف *, ثابت حرف *, صحيح);
#پایان_اگر /* !HAVE_SETENV */

#اگر_تعریف_نشده HAVE_SETLOGIN
صحيح setlogin(ثابت حرف *);
#پایان_اگر /* !HAVE_SETLOGIN */

#اگر_تعریف_نشده HAVE_INNETGR
صحيح innetgr(ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);
#پایان_اگر /* HAVE_INNETGR */

#إذا !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
صحيح seteuid(uid_t);
#پایان_اگر /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#إذا !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
صحيح setegid(uid_t);
#پایان_اگر /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#إذا !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ثابت حرف *strerror(صحيح);
#پایان_اگر

#إذا !defined(HAVE_SETLINEBUF)
#تعریف_کن setlinebuf(a)	(setvbuf((a), عدم, _IOLBF, 0))
#پایان_اگر

#اگر_تعریف_نشده HAVE_UTIMES
#اگر_تعریف_نشده HAVE_STRUCT_TIMEVAL
بنية timeval {
	دراز tv_sec;
	دراز tv_usec;
}
#پایان_اگر /* HAVE_STRUCT_TIMEVAL */

صحيح utimes(ثابت حرف *, بنية timeval *);
#پایان_اگر /* HAVE_UTIMES */

#اگر_تعریف_نشده HAVE_DIRFD
صحيح dirfd(فراغ *);
#پایان_اگر

#اگر_تعریف_نشده AT_FDCWD
# define AT_FDCWD (-2)
#پایان_اگر

#اگر_تعریف_نشده HAVE_FCHMODAT
صحيح fchmodat(صحيح, ثابت حرف *, نما_t, صحيح);
#پایان_اگر

#اگر_تعریف_نشده HAVE_FCHOWNAT
صحيح fchownat(صحيح, ثابت حرف *, uid_t, gid_t, صحيح);
#پایان_اگر

#اگر_تعریف_شده HAVE_FSTATAT
صحيح fstatat(صحيح, ثابت حرف *, بنية stat *, صحيح);
#پایان_اگر

#اگر_تعریف_شده HAVE_UNLINKAT
صحيح unlinkat(صحيح, ثابت حرف *, صحيح);
#پایان_اگر

#اگر_تعریف_نشده HAVE_TRUNCATE
صحيح truncate (ثابت حرف *, off_t);
#پایان_اگر /* HAVE_TRUNCATE */

#اگر_تعریف_نشده HAVE_STRUCT_TIMESPEC
بنية timespec {
	time_t	tv_sec;
	دراز	tv_nsec;
};
#پایان_اگر /* !HAVE_STRUCT_TIMESPEC */

#إذا !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
صحيح nanosleep(ثابت بنية timespec *, بنية timespec *);
#پایان_اگر

#اگر_تعریف_نشده HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
صحيح utimensat(صحيح, ثابت حرف *, ثابت بنية timespec[2], صحيح);
#پایان_اگر /* !HAVE_UTIMENSAT */

#اگر_تعریف_نشده HAVE_USLEEP
صحيح usleep(بیعلامت صحيح useconds);
#پایان_اگر

#اگر_تعریف_نشده HAVE_TCGETPGRP
pid_t tcgetpgrp(صحيح);
#پایان_اگر

#اگر_تعریف_نشده HAVE_TCSENDBREAK
صحيح tcsendbreak(صحيح, صحيح);
#پایان_اگر

#اگر_تعریف_نشده HAVE_UNSETENV
صحيح unsetenv(ثابت حرف *);
#پایان_اگر

#اگر_تعریف_نشده HAVE_ISBLANK
صحيح	isblank(صحيح);
#پایان_اگر

#اگر_تعریف_نشده HAVE_GETPGID
pid_t getpgid(pid_t);
#پایان_اگر

#اگر_تعریف_نشده HAVE_PSELECT
صحيح pselect(صحيح, fd_set *, fd_set *, fd_set *, ثابت بنية timespec *,
    ثابت sigset_t *);
#پایان_اگر

#اگر_تعریف_نشده HAVE_ENDGRENT
# define endgrent() افعل { } طالما(0)
#پایان_اگر

#اگر_تعریف_نشده HAVE_KRB5_GET_ERROR_پیام
# define krb5_get_error_پیام krb5_get_err_متن
#پایان_اگر

#اگر_تعریف_نشده HAVE_KRB5_FREE_ERROR_پیام
# define krb5_free_error_پیام(a,b) افعل { } طالما(0)
#پایان_اگر

#اگر_تعریف_نشده HAVE_PLEDGE
صحيح pledge(ثابت حرف *promises, ثابت حرف *execpromises);
#پایان_اگر

#اگر_تعریف_نشده HAVE_UNVEIL
صحيح unveil(ثابت حرف *, ثابت حرف *);
#پایان_اگر

/* bsd-err.h */
#اگر_تعریف_نشده HAVE_ERR
فراغ err(صحيح, ثابت حرف *, ...) __attribute__((format(چاپ_کن, 2, 3)));
#پایان_اگر
#اگر_تعریف_نشده HAVE_ERRX
فراغ errx(صحيح, ثابت حرف *, ...) __attribute__((format(چاپ_کن, 2, 3)));
#پایان_اگر
#اگر_تعریف_نشده HAVE_WARN
فراغ warn(ثابت حرف *, ...) __attribute__((format(چاپ_کن, 1, 2)));
#پایان_اگر

#اگر_تعریف_نشده HAVE_LLABS
دراز دراز llabs(دراز دراز);
#پایان_اگر

#إذا defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
فراغ bzero(فراغ *, اندازه_t);
#پایان_اگر

#اگر_تعریف_نشده HAVE_RAISE
صحيح ارفع(صحيح);
#پایان_اگر

#اگر_تعریف_نشده HAVE_GETSID
pid_t getsid(pid_t);
#پایان_اگر

#اگر_تعریف_نشده HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
صحيح flock(صحيح, صحيح);
#پایان_اگر

#اگر_تعریف_شده FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#پایان_اگر

#اگر_تعریف_نشده HAVE_LOCALTIME_R
بنية tm *localtime_r(ثابت time_t *, بنية tm *);
#پایان_اگر

#اگر_تعریف_نشده HAVE_CLOCK_GETTIME
تعريفنوع صحيح clockid_t;
#اگر_تعریف_نشده CLOCK_REALTIME
# define CLOCK_REALTIME	0
#پایان_اگر
صحيح clock_gettime(clockid_t, بنية timespec *);
#پایان_اگر

#اگر_تعریف_نشده HAVE_REALPATH
#تعریف_کن realpath(x, y)	(sftp_realpath((x), (y)))
#پایان_اگر

#پایان_اگر /* _BSD_MISC_H */
