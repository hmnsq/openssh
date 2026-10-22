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

#ضمن "includes.h"

حرف *ssh_get_progname(حرف *);
صحيح seed_from_prngd(unsigned حرف *, size_t);

#ifndef HAVE_SETSID
#define setsid() setpgrp(0, getpid())
#endif /* !HAVE_SETSID */

#ifndef HAVE_SETENV
صحيح setenv(ثابت حرف *, ثابت حرف *, صحيح);
#endif /* !HAVE_SETENV */

#ifndef HAVE_SETLOGIN
صحيح setlogin(ثابت حرف *);
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
صحيح innetgr(ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);
#endif /* HAVE_INNETGR */

#إذا !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
صحيح seteuid(uid_t);
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#إذا !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
صحيح setegid(uid_t);
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#إذا !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ثابت حرف *strerror(صحيح);
#endif

#إذا !defined(HAVE_SETLINEBUF)
#define setlinebuf(a)	(setvbuf((a), عدم, _IOLBF, 0))
#endif

#ifndef HAVE_UTIMES
#ifndef HAVE_STRUCT_TIMEVAL
بنية timeval {
	long tv_sec;
	long tv_usec;
}
#endif /* HAVE_STRUCT_TIMEVAL */

صحيح utimes(ثابت حرف *, بنية timeval *);
#endif /* HAVE_UTIMES */

#ifndef HAVE_DIRFD
صحيح dirfd(فراغ *);
#endif

#ifndef AT_FDCWD
# define AT_FDCWD (-2)
#endif

#ifndef HAVE_FCHMODAT
صحيح fchmodat(صحيح, ثابت حرف *, mode_t, صحيح);
#endif

#ifndef HAVE_FCHOWNAT
صحيح fchownat(صحيح, ثابت حرف *, uid_t, gid_t, صحيح);
#endif

#ifdef HAVE_FSTATAT
صحيح fstatat(صحيح, ثابت حرف *, بنية stat *, صحيح);
#endif

#ifdef HAVE_UNLINKAT
صحيح unlinkat(صحيح, ثابت حرف *, صحيح);
#endif

#ifndef HAVE_TRUNCATE
صحيح truncate (ثابت حرف *, off_t);
#endif /* HAVE_TRUNCATE */

#ifndef HAVE_STRUCT_TIMESPEC
بنية timespec {
	time_t	tv_sec;
	long	tv_nsec;
};
#endif /* !HAVE_STRUCT_TIMESPEC */

#إذا !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
صحيح nanosleep(ثابت بنية timespec *, بنية timespec *);
#endif

#ifndef HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
صحيح utimensat(صحيح, ثابت حرف *, ثابت بنية timespec[2], صحيح);
#endif /* !HAVE_UTIMENSAT */

#ifndef HAVE_USLEEP
صحيح usleep(unsigned صحيح useconds);
#endif

#ifndef HAVE_TCGETPGRP
pid_t tcgetpgrp(صحيح);
#endif

#ifndef HAVE_TCSENDBREAK
صحيح tcsendbreak(صحيح, صحيح);
#endif

#ifndef HAVE_UNSETENV
صحيح unsetenv(ثابت حرف *);
#endif

#ifndef HAVE_ISBLANK
صحيح	isblank(صحيح);
#endif

#ifndef HAVE_GETPGID
pid_t getpgid(pid_t);
#endif

#ifndef HAVE_PSELECT
صحيح pselect(صحيح, fd_set *, fd_set *, fd_set *, ثابت بنية timespec *,
    ثابت sigset_t *);
#endif

#ifndef HAVE_ENDGRENT
# define endgrent() افعل { } بينما(0)
#endif

#ifndef HAVE_KRB5_GET_ERROR_MESSAGE
# define krb5_get_error_message krb5_get_err_text
#endif

#ifndef HAVE_KRB5_FREE_ERROR_MESSAGE
# define krb5_free_error_message(a,b) افعل { } بينما(0)
#endif

#ifndef HAVE_PLEDGE
صحيح pledge(ثابت حرف *promises, ثابت حرف *execpromises);
#endif

#ifndef HAVE_UNVEIL
صحيح unveil(ثابت حرف *, ثابت حرف *);
#endif

/* bsd-err.h */
#ifndef HAVE_ERR
فراغ err(صحيح, ثابت حرف *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_ERRX
فراغ errx(صحيح, ثابت حرف *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_WARN
فراغ warn(ثابت حرف *, ...) __attribute__((format(printf, 1, 2)));
#endif

#ifndef HAVE_LLABS
long long llabs(long long);
#endif

#إذا defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
فراغ bzero(فراغ *, size_t);
#endif

#ifndef HAVE_RAISE
صحيح ارفع(صحيح);
#endif

#ifndef HAVE_GETSID
pid_t getsid(pid_t);
#endif

#ifndef HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
صحيح flock(صحيح, صحيح);
#endif

#ifdef FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#endif

#ifndef HAVE_LOCALTIME_R
بنية tm *localtime_r(ثابت time_t *, بنية tm *);
#endif

#ifndef HAVE_CLOCK_GETTIME
تعريفنوع صحيح clockid_t;
#ifndef CLOCK_REALTIME
# define CLOCK_REALTIME	0
#endif
صحيح clock_gettime(clockid_t, بنية timespec *);
#endif

#ifndef HAVE_REALPATH
#define realpath(x, y)	(sftp_realpath((x), (y)))
#endif

#endif /* _BSD_MISC_H */
