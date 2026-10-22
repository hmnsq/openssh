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

#অন্তর্ভাব "includes.h"

অক্ষর *ssh_get_progname(অক্ষর *);
পূর্ণসংখ্যা seed_from_prngd(unsigned অক্ষর *, আকার_t);

#ifndef HAVE_SETSID
#define setsid() setpgrp(0, getpid())
#endif /* !HAVE_SETSID */

#ifndef HAVE_SETENV
পূর্ণসংখ্যা setenv(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);
#endif /* !HAVE_SETENV */

#ifndef HAVE_SETLOGIN
পূর্ণসংখ্যা setlogin(ধ্রুবক অক্ষর *);
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
পূর্ণসংখ্যা innetgr(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
#endif /* HAVE_INNETGR */

#যদি !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
পূর্ণসংখ্যা seteuid(uid_t);
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#যদি !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
পূর্ণসংখ্যা setegid(uid_t);
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#যদি !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ধ্রুবক অক্ষর *strerror(পূর্ণসংখ্যা);
#endif

#যদি !defined(HAVE_SETLINEBUF)
#define setlinebuf(a)	(setvbuf((a), ফাঁকা, _IOLBF, 0))
#endif

#ifndef HAVE_UTIMES
#ifndef HAVE_STRUCT_TIMEVAL
কাঠামো timeval {
	long tv_sec;
	long tv_usec;
}
#endif /* HAVE_STRUCT_TIMEVAL */

পূর্ণসংখ্যা utimes(ধ্রুবক অক্ষর *, কাঠামো timeval *);
#endif /* HAVE_UTIMES */

#ifndef HAVE_DIRFD
পূর্ণসংখ্যা dirfd(শূন্য *);
#endif

#ifndef AT_FDCWD
# define AT_FDCWD (-2)
#endif

#ifndef HAVE_FCHMODAT
পূর্ণসংখ্যা fchmodat(পূর্ণসংখ্যা, ধ্রুবক অক্ষর *, mode_t, পূর্ণসংখ্যা);
#endif

#ifndef HAVE_FCHOWNAT
পূর্ণসংখ্যা fchownat(পূর্ণসংখ্যা, ধ্রুবক অক্ষর *, uid_t, gid_t, পূর্ণসংখ্যা);
#endif

#ifdef HAVE_FSTATAT
পূর্ণসংখ্যা fstatat(পূর্ণসংখ্যা, ধ্রুবক অক্ষর *, কাঠামো stat *, পূর্ণসংখ্যা);
#endif

#ifdef HAVE_UNLINKAT
পূর্ণসংখ্যা unlinkat(পূর্ণসংখ্যা, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);
#endif

#ifndef HAVE_TRUNCATE
পূর্ণসংখ্যা truncate (ধ্রুবক অক্ষর *, off_t);
#endif /* HAVE_TRUNCATE */

#ifndef HAVE_STRUCT_TIMESPEC
কাঠামো timespec {
	time_t	tv_sec;
	long	tv_nsec;
};
#endif /* !HAVE_STRUCT_TIMESPEC */

#যদি !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
পূর্ণসংখ্যা nanosleep(ধ্রুবক কাঠামো timespec *, কাঠামো timespec *);
#endif

#ifndef HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
পূর্ণসংখ্যা utimensat(পূর্ণসংখ্যা, ধ্রুবক অক্ষর *, ধ্রুবক কাঠামো timespec[2], পূর্ণসংখ্যা);
#endif /* !HAVE_UTIMENSAT */

#ifndef HAVE_USLEEP
পূর্ণসংখ্যা usleep(unsigned পূর্ণসংখ্যা useconds);
#endif

#ifndef HAVE_TCGETPGRP
pid_t tcgetpgrp(পূর্ণসংখ্যা);
#endif

#ifndef HAVE_TCSENDBREAK
পূর্ণসংখ্যা tcsendbreak(পূর্ণসংখ্যা, পূর্ণসংখ্যা);
#endif

#ifndef HAVE_UNSETENV
পূর্ণসংখ্যা unsetenv(ধ্রুবক অক্ষর *);
#endif

#ifndef HAVE_ISBLANK
পূর্ণসংখ্যা	isblank(পূর্ণসংখ্যা);
#endif

#ifndef HAVE_GETPGID
pid_t getpgid(pid_t);
#endif

#ifndef HAVE_PSELECT
পূর্ণসংখ্যা pselect(পূর্ণসংখ্যা, fd_set *, fd_set *, fd_set *, ধ্রুবক কাঠামো timespec *,
    ধ্রুবক sigset_t *);
#endif

#ifndef HAVE_ENDGRENT
# define endgrent() করো { } যখন(0)
#endif

#ifndef HAVE_KRB5_GET_ERROR_MESSAGE
# define krb5_get_error_message krb5_get_err_text
#endif

#ifndef HAVE_KRB5_FREE_ERROR_MESSAGE
# define krb5_free_error_message(a,b) করো { } যখন(0)
#endif

#ifndef HAVE_PLEDGE
পূর্ণসংখ্যা pledge(ধ্রুবক অক্ষর *promises, ধ্রুবক অক্ষর *execpromises);
#endif

#ifndef HAVE_UNVEIL
পূর্ণসংখ্যা unveil(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
#endif

/* bsd-err.h */
#ifndef HAVE_ERR
শূন্য err(পূর্ণসংখ্যা, ধ্রুবক অক্ষর *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_ERRX
শূন্য errx(পূর্ণসংখ্যা, ধ্রুবক অক্ষর *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_WARN
শূন্য warn(ধ্রুবক অক্ষর *, ...) __attribute__((format(printf, 1, 2)));
#endif

#ifndef HAVE_LLABS
long long llabs(long long);
#endif

#যদি defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
শূন্য bzero(শূন্য *, আকার_t);
#endif

#ifndef HAVE_RAISE
পূর্ণসংখ্যা তোলো(পূর্ণসংখ্যা);
#endif

#ifndef HAVE_GETSID
pid_t getsid(pid_t);
#endif

#ifndef HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
পূর্ণসংখ্যা flock(পূর্ণসংখ্যা, পূর্ণসংখ্যা);
#endif

#ifdef FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#endif

#ifndef HAVE_LOCALTIME_R
কাঠামো tm *localtime_r(ধ্রুবক time_t *, কাঠামো tm *);
#endif

#ifndef HAVE_CLOCK_GETTIME
প্রকারলেখ পূর্ণসংখ্যা clockid_t;
#ifndef CLOCK_REALTIME
# define CLOCK_REALTIME	0
#endif
পূর্ণসংখ্যা clock_gettime(clockid_t, কাঠামো timespec *);
#endif

#ifndef HAVE_REALPATH
#define realpath(x, y)	(sftp_realpath((x), (y)))
#endif

#endif /* _BSD_MISC_H */
