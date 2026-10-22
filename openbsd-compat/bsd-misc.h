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

#جے_بنا_تعریف _BSD_MISC_H
#تعریف_کرو _BSD_MISC_H

#ضمن "includes.h"

حرف *ssh_get_progname(حرف *);
صحيح بیج_from_prngd(بنانشانی حرف *, ناپ_t);

#جے_بنا_تعریف HAVE_SETSID
#تعریف_کرو setsid() setpgrp(0, getpid())
#جے_انت /* !HAVE_SETSID */

#جے_بنا_تعریف HAVE_SETENV
صحيح setenv(ثابت حرف *, ثابت حرف *, صحيح);
#جے_انت /* !HAVE_SETENV */

#جے_بنا_تعریف HAVE_SETLOGIN
صحيح setlogin(ثابت حرف *);
#جے_انت /* !HAVE_SETLOGIN */

#جے_بنا_تعریف HAVE_INNETGR
صحيح innetgr(ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);
#جے_انت /* HAVE_INNETGR */

#إذا !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
صحيح seteuid(uid_t);
#جے_انت /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#إذا !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
صحيح setegid(uid_t);
#جے_انت /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#إذا !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ثابت حرف *strerror(صحيح);
#جے_انت

#إذا !defined(HAVE_SETLINEBUF)
#تعریف_کرو setlinebuf(a)	(setvbuf((a), عدم, _IOLBF, 0))
#جے_انت

#جے_بنا_تعریف HAVE_UTIMES
#جے_بنا_تعریف HAVE_STRUCT_TIMEVAL
بنية timeval {
	لما tv_sec;
	لما tv_usec;
}
#جے_انت /* HAVE_STRUCT_TIMEVAL */

صحيح utimes(ثابت حرف *, بنية timeval *);
#جے_انت /* HAVE_UTIMES */

#جے_بنا_تعریف HAVE_DIRFD
صحيح dirfd(فراغ *);
#جے_انت

#جے_بنا_تعریف AT_FDCWD
# define AT_FDCWD (-2)
#جے_انت

#جے_بنا_تعریف HAVE_FCHMODAT
صحيح fchmodat(صحيح, ثابت حرف *, منوال_t, صحيح);
#جے_انت

#جے_بنا_تعریف HAVE_FCHOWNAT
صحيح fchownat(صحيح, ثابت حرف *, uid_t, gid_t, صحيح);
#جے_انت

#جے_تعریف_شدہ HAVE_FSTATAT
صحيح fstatat(صحيح, ثابت حرف *, بنية stat *, صحيح);
#جے_انت

#جے_تعریف_شدہ HAVE_UNLINKAT
صحيح unlinkat(صحيح, ثابت حرف *, صحيح);
#جے_انت

#جے_بنا_تعریف HAVE_TRUNCATE
صحيح truncate (ثابت حرف *, off_t);
#جے_انت /* HAVE_TRUNCATE */

#جے_بنا_تعریف HAVE_STRUCT_TIMESPEC
بنية timespec {
	time_t	tv_sec;
	لما	tv_nsec;
};
#جے_انت /* !HAVE_STRUCT_TIMESPEC */

#إذا !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
صحيح nanosleep(ثابت بنية timespec *, بنية timespec *);
#جے_انت

#جے_بنا_تعریف HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
صحيح utimensat(صحيح, ثابت حرف *, ثابت بنية timespec[2], صحيح);
#جے_انت /* !HAVE_UTIMENSAT */

#جے_بنا_تعریف HAVE_USLEEP
صحيح usleep(بنانشانی صحيح useconds);
#جے_انت

#جے_بنا_تعریف HAVE_TCGETPGRP
pid_t tcgetpgrp(صحيح);
#جے_انت

#جے_بنا_تعریف HAVE_TCSENDBREAK
صحيح tcsendbreak(صحيح, صحيح);
#جے_انت

#جے_بنا_تعریف HAVE_UNSETENV
صحيح unsetenv(ثابت حرف *);
#جے_انت

#جے_بنا_تعریف HAVE_ISBLANK
صحيح	isblank(صحيح);
#جے_انت

#جے_بنا_تعریف HAVE_GETPGID
pid_t getpgid(pid_t);
#جے_انت

#جے_بنا_تعریف HAVE_PSELECT
صحيح pselect(صحيح, fd_set *, fd_set *, fd_set *, ثابت بنية timespec *,
    ثابت sigset_t *);
#جے_انت

#جے_بنا_تعریف HAVE_ENDGRENT
# define endgrent() افعل { } طالما(0)
#جے_انت

#جے_بنا_تعریف HAVE_KRB5_GET_ERROR_سنیہا
# define krb5_get_error_سنیہا krb5_get_err_متن
#جے_انت

#جے_بنا_تعریف HAVE_KRB5_FREE_ERROR_سنیہا
# define krb5_free_error_سنیہا(a,b) افعل { } طالما(0)
#جے_انت

#جے_بنا_تعریف HAVE_PLEDGE
صحيح pledge(ثابت حرف *promises, ثابت حرف *execpromises);
#جے_انت

#جے_بنا_تعریف HAVE_UNVEIL
صحيح unveil(ثابت حرف *, ثابت حرف *);
#جے_انت

/* bsd-err.h */
#جے_بنا_تعریف HAVE_ERR
فراغ err(صحيح, ثابت حرف *, ...) __attribute__((format(لکھو, 2, 3)));
#جے_انت
#جے_بنا_تعریف HAVE_ERRX
فراغ errx(صحيح, ثابت حرف *, ...) __attribute__((format(لکھو, 2, 3)));
#جے_انت
#جے_بنا_تعریف HAVE_WARN
فراغ warn(ثابت حرف *, ...) __attribute__((format(لکھو, 1, 2)));
#جے_انت

#جے_بنا_تعریف HAVE_LLABS
لما لما llabs(لما لما);
#جے_انت

#إذا defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
فراغ bzero(فراغ *, ناپ_t);
#جے_انت

#جے_بنا_تعریف HAVE_RAISE
صحيح ارفع(صحيح);
#جے_انت

#جے_بنا_تعریف HAVE_GETSID
pid_t getsid(pid_t);
#جے_انت

#جے_بنا_تعریف HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
صحيح flock(صحيح, صحيح);
#جے_انت

#جے_تعریف_شدہ FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#جے_انت

#جے_بنا_تعریف HAVE_LOCALTIME_R
بنية tm *localtime_r(ثابت time_t *, بنية tm *);
#جے_انت

#جے_بنا_تعریف HAVE_CLOCK_GETTIME
تعريفنوع صحيح clockid_t;
#جے_بنا_تعریف CLOCK_REALTIME
# define CLOCK_REALTIME	0
#جے_انت
صحيح clock_gettime(clockid_t, بنية timespec *);
#جے_انت

#جے_بنا_تعریف HAVE_REALPATH
#تعریف_کرو realpath(x, y)	(sftp_realpath((x), (y)))
#جے_انت

#جے_انت /* _BSD_MISC_H */
