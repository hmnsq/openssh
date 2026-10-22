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

#جيڪڏهن_وصف_نه_ٿيل _BSD_MISC_H
#وصف_ڪريو _BSD_MISC_H

#ضمن "includes.h"

حرف *ssh_get_progname(حرف *);
صحيح ٻج_from_prngd(بنانشان حرف *, سائيز_t);

#جيڪڏهن_وصف_نه_ٿيل HAVE_SETSID
#وصف_ڪريو setsid() setpgrp(0, getpid())
#جيڪڏهن_پورو /* !HAVE_SETSID */

#جيڪڏهن_وصف_نه_ٿيل HAVE_SETENV
صحيح setenv(ثابت حرف *, ثابت حرف *, صحيح);
#جيڪڏهن_پورو /* !HAVE_SETENV */

#جيڪڏهن_وصف_نه_ٿيل HAVE_SETLOGIN
صحيح setlogin(ثابت حرف *);
#جيڪڏهن_پورو /* !HAVE_SETLOGIN */

#جيڪڏهن_وصف_نه_ٿيل HAVE_INNETGR
صحيح innetgr(ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);
#جيڪڏهن_پورو /* HAVE_INNETGR */

#إذا !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
صحيح seteuid(uid_t);
#جيڪڏهن_پورو /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#إذا !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
صحيح setegid(uid_t);
#جيڪڏهن_پورو /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#إذا !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ثابت حرف *strerror(صحيح);
#جيڪڏهن_پورو

#إذا !defined(HAVE_SETLINEBUF)
#وصف_ڪريو setlinebuf(a)	(setvbuf((a), عدم, _IOLBF, 0))
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_UTIMES
#جيڪڏهن_وصف_نه_ٿيل HAVE_STRUCT_TIMEVAL
بنية timeval {
	ڊگهو tv_sec;
	ڊگهو tv_usec;
}
#جيڪڏهن_پورو /* HAVE_STRUCT_TIMEVAL */

صحيح utimes(ثابت حرف *, بنية timeval *);
#جيڪڏهن_پورو /* HAVE_UTIMES */

#جيڪڏهن_وصف_نه_ٿيل HAVE_DIRFD
صحيح dirfd(فراغ *);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل AT_FDCWD
# define AT_FDCWD (-2)
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_FCHMODAT
صحيح fchmodat(صحيح, ثابت حرف *, گهڻائي_t, صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_FCHOWNAT
صحيح fchownat(صحيح, ثابت حرف *, uid_t, gid_t, صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل HAVE_FSTATAT
صحيح fstatat(صحيح, ثابت حرف *, بنية stat *, صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل HAVE_UNLINKAT
صحيح unlinkat(صحيح, ثابت حرف *, صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_TRUNCATE
صحيح truncate (ثابت حرف *, off_t);
#جيڪڏهن_پورو /* HAVE_TRUNCATE */

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRUCT_TIMESPEC
بنية timespec {
	time_t	tv_sec;
	ڊگهو	tv_nsec;
};
#جيڪڏهن_پورو /* !HAVE_STRUCT_TIMESPEC */

#إذا !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
صحيح nanosleep(ثابت بنية timespec *, بنية timespec *);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
صحيح utimensat(صحيح, ثابت حرف *, ثابت بنية timespec[2], صحيح);
#جيڪڏهن_پورو /* !HAVE_UTIMENSAT */

#جيڪڏهن_وصف_نه_ٿيل HAVE_USLEEP
صحيح usleep(بنانشان صحيح useconds);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_TCGETPGRP
pid_t tcgetpgrp(صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_TCSENDBREAK
صحيح tcsendbreak(صحيح, صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_UNSETENV
صحيح unsetenv(ثابت حرف *);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_ISBLANK
صحيح	isblank(صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_GETPGID
pid_t getpgid(pid_t);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_PSELECT
صحيح pselect(صحيح, fd_set *, fd_set *, fd_set *, ثابت بنية timespec *,
    ثابت sigset_t *);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_ENDGRENT
# define endgrent() افعل { } طالما(0)
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_KRB5_GET_ERROR_پيغام
# define krb5_get_error_پيغام krb5_get_err_متن
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_KRB5_FREE_ERROR_پيغام
# define krb5_free_error_پيغام(a,b) افعل { } طالما(0)
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_PLEDGE
صحيح pledge(ثابت حرف *promises, ثابت حرف *execpromises);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_UNVEIL
صحيح unveil(ثابت حرف *, ثابت حرف *);
#جيڪڏهن_پورو

/* bsd-err.h */
#جيڪڏهن_وصف_نه_ٿيل HAVE_ERR
فراغ err(صحيح, ثابت حرف *, ...) __attribute__((format(لکو, 2, 3)));
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل HAVE_ERRX
فراغ errx(صحيح, ثابت حرف *, ...) __attribute__((format(لکو, 2, 3)));
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل HAVE_WARN
فراغ warn(ثابت حرف *, ...) __attribute__((format(لکو, 1, 2)));
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_LLABS
ڊگهو ڊگهو llabs(ڊگهو ڊگهو);
#جيڪڏهن_پورو

#إذا defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
فراغ bzero(فراغ *, سائيز_t);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_RAISE
صحيح ارفع(صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_GETSID
pid_t getsid(pid_t);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
صحيح flock(صحيح, صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_LOCALTIME_R
بنية tm *localtime_r(ثابت time_t *, بنية tm *);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_CLOCK_GETTIME
تعريفنوع صحيح clockid_t;
#جيڪڏهن_وصف_نه_ٿيل CLOCK_REALTIME
# define CLOCK_REALTIME	0
#جيڪڏهن_پورو
صحيح clock_gettime(clockid_t, بنية timespec *);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_REALPATH
#وصف_ڪريو realpath(x, y)	(sftp_realpath((x), (y)))
#جيڪڏهن_پورو

#جيڪڏهن_پورو /* _BSD_MISC_H */
