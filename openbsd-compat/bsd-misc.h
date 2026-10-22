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

#که_نه_تعریف_شوی _BSD_MISC_H
#تعریف_کړه _BSD_MISC_H

#ضمن "includes.h"

حرف *ssh_get_progname(حرف *);
صحيح تخم_from_prngd(بینښه حرف *, اندازه_t);

#که_نه_تعریف_شوی HAVE_SETSID
#تعریف_کړه setsid() setpgrp(0, getpid())
#د_که_پای /* !HAVE_SETSID */

#که_نه_تعریف_شوی HAVE_SETENV
صحيح setenv(ثابت حرف *, ثابت حرف *, صحيح);
#د_که_پای /* !HAVE_SETENV */

#که_نه_تعریف_شوی HAVE_SETLOGIN
صحيح setlogin(ثابت حرف *);
#د_که_پای /* !HAVE_SETLOGIN */

#که_نه_تعریف_شوی HAVE_INNETGR
صحيح innetgr(ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);
#د_که_پای /* HAVE_INNETGR */

#إذا !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
صحيح seteuid(uid_t);
#د_که_پای /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#إذا !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
صحيح setegid(uid_t);
#د_که_پای /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#إذا !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ثابت حرف *strerror(صحيح);
#د_که_پای

#إذا !defined(HAVE_SETLINEBUF)
#تعریف_کړه setlinebuf(a)	(setvbuf((a), عدم, _IOLBF, 0))
#د_که_پای

#که_نه_تعریف_شوی HAVE_UTIMES
#که_نه_تعریف_شوی HAVE_STRUCT_TIMEVAL
بنية timeval {
	اوږد tv_sec;
	اوږد tv_usec;
}
#د_که_پای /* HAVE_STRUCT_TIMEVAL */

صحيح utimes(ثابت حرف *, بنية timeval *);
#د_که_پای /* HAVE_UTIMES */

#که_نه_تعریف_شوی HAVE_DIRFD
صحيح dirfd(فراغ *);
#د_که_پای

#که_نه_تعریف_شوی AT_FDCWD
# define AT_FDCWD (-2)
#د_که_پای

#که_نه_تعریف_شوی HAVE_FCHMODAT
صحيح fchmodat(صحيح, ثابت حرف *, ډېرپېښ_t, صحيح);
#د_که_پای

#که_نه_تعریف_شوی HAVE_FCHOWNAT
صحيح fchownat(صحيح, ثابت حرف *, uid_t, gid_t, صحيح);
#د_که_پای

#که_تعریف_شوی HAVE_FSTATAT
صحيح fstatat(صحيح, ثابت حرف *, بنية stat *, صحيح);
#د_که_پای

#که_تعریف_شوی HAVE_UNLINKAT
صحيح unlinkat(صحيح, ثابت حرف *, صحيح);
#د_که_پای

#که_نه_تعریف_شوی HAVE_TRUNCATE
صحيح truncate (ثابت حرف *, off_t);
#د_که_پای /* HAVE_TRUNCATE */

#که_نه_تعریف_شوی HAVE_STRUCT_TIMESPEC
بنية timespec {
	time_t	tv_sec;
	اوږد	tv_nsec;
};
#د_که_پای /* !HAVE_STRUCT_TIMESPEC */

#إذا !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
صحيح nanosleep(ثابت بنية timespec *, بنية timespec *);
#د_که_پای

#که_نه_تعریف_شوی HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
صحيح utimensat(صحيح, ثابت حرف *, ثابت بنية timespec[2], صحيح);
#د_که_پای /* !HAVE_UTIMENSAT */

#که_نه_تعریف_شوی HAVE_USLEEP
صحيح usleep(بینښه صحيح useconds);
#د_که_پای

#که_نه_تعریف_شوی HAVE_TCGETPGRP
pid_t tcgetpgrp(صحيح);
#د_که_پای

#که_نه_تعریف_شوی HAVE_TCSENDBREAK
صحيح tcsendbreak(صحيح, صحيح);
#د_که_پای

#که_نه_تعریف_شوی HAVE_UNSETENV
صحيح unsetenv(ثابت حرف *);
#د_که_پای

#که_نه_تعریف_شوی HAVE_ISBLANK
صحيح	isblank(صحيح);
#د_که_پای

#که_نه_تعریف_شوی HAVE_GETPGID
pid_t getpgid(pid_t);
#د_که_پای

#که_نه_تعریف_شوی HAVE_PSELECT
صحيح pselect(صحيح, fd_set *, fd_set *, fd_set *, ثابت بنية timespec *,
    ثابت sigset_t *);
#د_که_پای

#که_نه_تعریف_شوی HAVE_ENDGRENT
# define endgrent() افعل { } طالما(0)
#د_که_پای

#که_نه_تعریف_شوی HAVE_KRB5_GET_ERROR_پیغام
# define krb5_get_error_پیغام krb5_get_err_متن
#د_که_پای

#که_نه_تعریف_شوی HAVE_KRB5_FREE_ERROR_پیغام
# define krb5_free_error_پیغام(a,b) افعل { } طالما(0)
#د_که_پای

#که_نه_تعریف_شوی HAVE_PLEDGE
صحيح pledge(ثابت حرف *promises, ثابت حرف *execpromises);
#د_که_پای

#که_نه_تعریف_شوی HAVE_UNVEIL
صحيح unveil(ثابت حرف *, ثابت حرف *);
#د_که_پای

/* bsd-err.h */
#که_نه_تعریف_شوی HAVE_ERR
فراغ err(صحيح, ثابت حرف *, ...) __attribute__((format(چاپ_کړه, 2, 3)));
#د_که_پای
#که_نه_تعریف_شوی HAVE_ERRX
فراغ errx(صحيح, ثابت حرف *, ...) __attribute__((format(چاپ_کړه, 2, 3)));
#د_که_پای
#که_نه_تعریف_شوی HAVE_WARN
فراغ warn(ثابت حرف *, ...) __attribute__((format(چاپ_کړه, 1, 2)));
#د_که_پای

#که_نه_تعریف_شوی HAVE_LLABS
اوږد اوږد llabs(اوږد اوږد);
#د_که_پای

#إذا defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
فراغ bzero(فراغ *, اندازه_t);
#د_که_پای

#که_نه_تعریف_شوی HAVE_RAISE
صحيح ارفع(صحيح);
#د_که_پای

#که_نه_تعریف_شوی HAVE_GETSID
pid_t getsid(pid_t);
#د_که_پای

#که_نه_تعریف_شوی HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
صحيح flock(صحيح, صحيح);
#د_که_پای

#که_تعریف_شوی FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#د_که_پای

#که_نه_تعریف_شوی HAVE_LOCALTIME_R
بنية tm *localtime_r(ثابت time_t *, بنية tm *);
#د_که_پای

#که_نه_تعریف_شوی HAVE_CLOCK_GETTIME
تعريفنوع صحيح clockid_t;
#که_نه_تعریف_شوی CLOCK_REALTIME
# define CLOCK_REALTIME	0
#د_که_پای
صحيح clock_gettime(clockid_t, بنية timespec *);
#د_که_پای

#که_نه_تعریف_شوی HAVE_REALPATH
#تعریف_کړه realpath(x, y)	(sftp_realpath((x), (y)))
#د_که_پای

#د_که_پای /* _BSD_MISC_H */
