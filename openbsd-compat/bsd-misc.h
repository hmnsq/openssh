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

#அந்தர்பாவ "includes.h"

எழுத்து *ssh_get_progname(எழுத்து *);
முழு seed_from_prngd(unsigned எழுத்து *, size_t);

#ifndef HAVE_SETSID
#define setsid() setpgrp(0, getpid())
#endif /* !HAVE_SETSID */

#ifndef HAVE_SETENV
முழு setenv(மாறிலி எழுத்து *, மாறிலி எழுத்து *, முழு);
#endif /* !HAVE_SETENV */

#ifndef HAVE_SETLOGIN
முழு setlogin(மாறிலி எழுத்து *);
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
முழு innetgr(மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *);
#endif /* HAVE_INNETGR */

#எனில் !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
முழு seteuid(uid_t);
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#எனில் !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
முழு setegid(uid_t);
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#எனில் !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
மாறிலி எழுத்து *strerror(முழு);
#endif

#எனில் !defined(HAVE_SETLINEBUF)
#define setlinebuf(a)	(setvbuf((a), வெற்று, _IOLBF, 0))
#endif

#ifndef HAVE_UTIMES
#ifndef HAVE_STRUCT_TIMEVAL
கட்டமைப்பு timeval {
	long tv_sec;
	long tv_usec;
}
#endif /* HAVE_STRUCT_TIMEVAL */

முழு utimes(மாறிலி எழுத்து *, கட்டமைப்பு timeval *);
#endif /* HAVE_UTIMES */

#ifndef HAVE_DIRFD
முழு dirfd(வெறுமை *);
#endif

#ifndef AT_FDCWD
# define AT_FDCWD (-2)
#endif

#ifndef HAVE_FCHMODAT
முழு fchmodat(முழு, மாறிலி எழுத்து *, mode_t, முழு);
#endif

#ifndef HAVE_FCHOWNAT
முழு fchownat(முழு, மாறிலி எழுத்து *, uid_t, gid_t, முழு);
#endif

#ifdef HAVE_FSTATAT
முழு fstatat(முழு, மாறிலி எழுத்து *, கட்டமைப்பு stat *, முழு);
#endif

#ifdef HAVE_UNLINKAT
முழு unlinkat(முழு, மாறிலி எழுத்து *, முழு);
#endif

#ifndef HAVE_TRUNCATE
முழு truncate (மாறிலி எழுத்து *, off_t);
#endif /* HAVE_TRUNCATE */

#ifndef HAVE_STRUCT_TIMESPEC
கட்டமைப்பு timespec {
	time_t	tv_sec;
	long	tv_nsec;
};
#endif /* !HAVE_STRUCT_TIMESPEC */

#எனில் !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
முழு nanosleep(மாறிலி கட்டமைப்பு timespec *, கட்டமைப்பு timespec *);
#endif

#ifndef HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
முழு utimensat(முழு, மாறிலி எழுத்து *, மாறிலி கட்டமைப்பு timespec[2], முழு);
#endif /* !HAVE_UTIMENSAT */

#ifndef HAVE_USLEEP
முழு usleep(unsigned முழு useconds);
#endif

#ifndef HAVE_TCGETPGRP
pid_t tcgetpgrp(முழு);
#endif

#ifndef HAVE_TCSENDBREAK
முழு tcsendbreak(முழு, முழு);
#endif

#ifndef HAVE_UNSETENV
முழு unsetenv(மாறிலி எழுத்து *);
#endif

#ifndef HAVE_ISBLANK
முழு	isblank(முழு);
#endif

#ifndef HAVE_GETPGID
pid_t getpgid(pid_t);
#endif

#ifndef HAVE_PSELECT
முழு pselect(முழு, fd_set *, fd_set *, fd_set *, மாறிலி கட்டமைப்பு timespec *,
    மாறிலி sigset_t *);
#endif

#ifndef HAVE_ENDGRENT
# define endgrent() செய் { } போது(0)
#endif

#ifndef HAVE_KRB5_GET_ERROR_MESSAGE
# define krb5_get_error_message krb5_get_err_text
#endif

#ifndef HAVE_KRB5_FREE_ERROR_MESSAGE
# define krb5_free_error_message(a,b) செய் { } போது(0)
#endif

#ifndef HAVE_PLEDGE
முழு pledge(மாறிலி எழுத்து *promises, மாறிலி எழுத்து *execpromises);
#endif

#ifndef HAVE_UNVEIL
முழு unveil(மாறிலி எழுத்து *, மாறிலி எழுத்து *);
#endif

/* bsd-err.h */
#ifndef HAVE_ERR
வெறுமை err(முழு, மாறிலி எழுத்து *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_ERRX
வெறுமை errx(முழு, மாறிலி எழுத்து *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_WARN
வெறுமை warn(மாறிலி எழுத்து *, ...) __attribute__((format(printf, 1, 2)));
#endif

#ifndef HAVE_LLABS
long long llabs(long long);
#endif

#எனில் defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
வெறுமை bzero(வெறுமை *, size_t);
#endif

#ifndef HAVE_RAISE
முழு எழுப்பு(முழு);
#endif

#ifndef HAVE_GETSID
pid_t getsid(pid_t);
#endif

#ifndef HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
முழு flock(முழு, முழு);
#endif

#ifdef FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#endif

#ifndef HAVE_LOCALTIME_R
கட்டமைப்பு tm *localtime_r(மாறிலி time_t *, கட்டமைப்பு tm *);
#endif

#ifndef HAVE_CLOCK_GETTIME
வகைவரை முழு clockid_t;
#ifndef CLOCK_REALTIME
# define CLOCK_REALTIME	0
#endif
முழு clock_gettime(clockid_t, கட்டமைப்பு timespec *);
#endif

#ifndef HAVE_REALPATH
#define realpath(x, y)	(sftp_realpath((x), (y)))
#endif

#endif /* _BSD_MISC_H */
