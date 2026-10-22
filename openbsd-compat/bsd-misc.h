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

বর্ণ *ssh_get_progname(বর্ণ *);
পূর্ণাঙ্ক seed_from_prngd(unsigned বর্ণ *, size_t);

#ifndef HAVE_SETSID
#define setsid() setpgrp(0, getpid())
#endif /* !HAVE_SETSID */

#ifndef HAVE_SETENV
পূর্ণাঙ্ক setenv(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, পূর্ণাঙ্ক);
#endif /* !HAVE_SETENV */

#ifndef HAVE_SETLOGIN
পূর্ণাঙ্ক setlogin(ধ্রুব বর্ণ *);
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
পূর্ণাঙ্ক innetgr(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);
#endif /* HAVE_INNETGR */

#যদি !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
পূর্ণাঙ্ক seteuid(uid_t);
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#যদি !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
পূর্ণাঙ্ক setegid(uid_t);
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#যদি !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ধ্রুব বর্ণ *strerror(পূর্ণাঙ্ক);
#endif

#যদি !defined(HAVE_SETLINEBUF)
#define setlinebuf(a)	(setvbuf((a), রিক্ত, _IOLBF, 0))
#endif

#ifndef HAVE_UTIMES
#ifndef HAVE_STRUCT_TIMEVAL
সংরচনা timeval {
	long tv_sec;
	long tv_usec;
}
#endif /* HAVE_STRUCT_TIMEVAL */

পূর্ণাঙ্ক utimes(ধ্রুব বর্ণ *, সংরচনা timeval *);
#endif /* HAVE_UTIMES */

#ifndef HAVE_DIRFD
পূর্ণাঙ্ক dirfd(শূন্য *);
#endif

#ifndef AT_FDCWD
# define AT_FDCWD (-2)
#endif

#ifndef HAVE_FCHMODAT
পূর্ণাঙ্ক fchmodat(পূর্ণাঙ্ক, ধ্রুব বর্ণ *, mode_t, পূর্ণাঙ্ক);
#endif

#ifndef HAVE_FCHOWNAT
পূর্ণাঙ্ক fchownat(পূর্ণাঙ্ক, ধ্রুব বর্ণ *, uid_t, gid_t, পূর্ণাঙ্ক);
#endif

#ifdef HAVE_FSTATAT
পূর্ণাঙ্ক fstatat(পূর্ণাঙ্ক, ধ্রুব বর্ণ *, সংরচনা stat *, পূর্ণাঙ্ক);
#endif

#ifdef HAVE_UNLINKAT
পূর্ণাঙ্ক unlinkat(পূর্ণাঙ্ক, ধ্রুব বর্ণ *, পূর্ণাঙ্ক);
#endif

#ifndef HAVE_TRUNCATE
পূর্ণাঙ্ক truncate (ধ্রুব বর্ণ *, off_t);
#endif /* HAVE_TRUNCATE */

#ifndef HAVE_STRUCT_TIMESPEC
সংরচনা timespec {
	time_t	tv_sec;
	long	tv_nsec;
};
#endif /* !HAVE_STRUCT_TIMESPEC */

#যদি !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
পূর্ণাঙ্ক nanosleep(ধ্রুব সংরচনা timespec *, সংরচনা timespec *);
#endif

#ifndef HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
পূর্ণাঙ্ক utimensat(পূর্ণাঙ্ক, ধ্রুব বর্ণ *, ধ্রুব সংরচনা timespec[2], পূর্ণাঙ্ক);
#endif /* !HAVE_UTIMENSAT */

#ifndef HAVE_USLEEP
পূর্ণাঙ্ক usleep(unsigned পূর্ণাঙ্ক useconds);
#endif

#ifndef HAVE_TCGETPGRP
pid_t tcgetpgrp(পূর্ণাঙ্ক);
#endif

#ifndef HAVE_TCSENDBREAK
পূর্ণাঙ্ক tcsendbreak(পূর্ণাঙ্ক, পূর্ণাঙ্ক);
#endif

#ifndef HAVE_UNSETENV
পূর্ণাঙ্ক unsetenv(ধ্রুব বর্ণ *);
#endif

#ifndef HAVE_ISBLANK
পূর্ণাঙ্ক	isblank(পূর্ণাঙ্ক);
#endif

#ifndef HAVE_GETPGID
pid_t getpgid(pid_t);
#endif

#ifndef HAVE_PSELECT
পূর্ণাঙ্ক pselect(পূর্ণাঙ্ক, fd_set *, fd_set *, fd_set *, ধ্রুব সংরচনা timespec *,
    ধ্রুব sigset_t *);
#endif

#ifndef HAVE_ENDGRENT
# define endgrent() কুরু { } যাবত্(0)
#endif

#ifndef HAVE_KRB5_GET_ERROR_MESSAGE
# define krb5_get_error_message krb5_get_err_text
#endif

#ifndef HAVE_KRB5_FREE_ERROR_MESSAGE
# define krb5_free_error_message(a,b) কুরু { } যাবত্(0)
#endif

#ifndef HAVE_PLEDGE
পূর্ণাঙ্ক pledge(ধ্রুব বর্ণ *promises, ধ্রুব বর্ণ *execpromises);
#endif

#ifndef HAVE_UNVEIL
পূর্ণাঙ্ক unveil(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);
#endif

/* bsd-err.h */
#ifndef HAVE_ERR
শূন্য err(পূর্ণাঙ্ক, ধ্রুব বর্ণ *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_ERRX
শূন্য errx(পূর্ণাঙ্ক, ধ্রুব বর্ণ *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_WARN
শূন্য warn(ধ্রুব বর্ণ *, ...) __attribute__((format(printf, 1, 2)));
#endif

#ifndef HAVE_LLABS
long long llabs(long long);
#endif

#যদি defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
শূন্য bzero(শূন্য *, size_t);
#endif

#ifndef HAVE_RAISE
পূর্ণাঙ্ক উত্থাপয(পূর্ণাঙ্ক);
#endif

#ifndef HAVE_GETSID
pid_t getsid(pid_t);
#endif

#ifndef HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
পূর্ণাঙ্ক flock(পূর্ণাঙ্ক, পূর্ণাঙ্ক);
#endif

#ifdef FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#endif

#ifndef HAVE_LOCALTIME_R
সংরচনা tm *localtime_r(ধ্রুব time_t *, সংরচনা tm *);
#endif

#ifndef HAVE_CLOCK_GETTIME
প্রকারনির্দেশ পূর্ণাঙ্ক clockid_t;
#ifndef CLOCK_REALTIME
# define CLOCK_REALTIME	0
#endif
পূর্ণাঙ্ক clock_gettime(clockid_t, সংরচনা timespec *);
#endif

#ifndef HAVE_REALPATH
#define realpath(x, y)	(sftp_realpath((x), (y)))
#endif

#endif /* _BSD_MISC_H */
