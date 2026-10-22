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

#include "includes.h"

char *ssh_get_progname(char *);
цяло seed_from_prngd(unsigned char *, size_t);

#ifndef HAVE_SETSID
#define setsid() setpgrp(0, getpid())
#endif /* !HAVE_SETSID */

#ifndef HAVE_SETENV
цяло setenv(const char *, const char *, цяло);
#endif /* !HAVE_SETENV */

#ifndef HAVE_SETLOGIN
цяло setlogin(const char *);
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
цяло innetgr(const char *, const char *, const char *, const char *);
#endif /* HAVE_INNETGR */

#ако !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
цяло seteuid(uid_t);
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ако !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
цяло setegid(uid_t);
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ако !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const char *strerror(цяло);
#endif

#ако !defined(HAVE_SETLINEBUF)
#define setlinebuf(a)	(setvbuf((a), NULL, _IOLBF, 0))
#endif

#ifndef HAVE_UTIMES
#ifndef HAVE_STRUCT_TIMEVAL
struct timeval {
	long tv_sec;
	long tv_usec;
}
#endif /* HAVE_STRUCT_TIMEVAL */

цяло utimes(const char *, struct timeval *);
#endif /* HAVE_UTIMES */

#ifndef HAVE_DIRFD
цяло dirfd(void *);
#endif

#ifndef AT_FDCWD
# define AT_FDCWD (-2)
#endif

#ifndef HAVE_FCHMODAT
цяло fchmodat(цяло, const char *, mode_t, цяло);
#endif

#ifndef HAVE_FCHOWNAT
цяло fchownat(цяло, const char *, uid_t, gid_t, цяло);
#endif

#ifdef HAVE_FSTATAT
цяло fstatat(цяло, const char *, struct stat *, цяло);
#endif

#ifdef HAVE_UNLINKAT
цяло unlinkat(цяло, const char *, цяло);
#endif

#ifndef HAVE_TRUNCATE
цяло truncate (const char *, off_t);
#endif /* HAVE_TRUNCATE */

#ifndef HAVE_STRUCT_TIMESPEC
struct timespec {
	time_t	tv_sec;
	long	tv_nsec;
};
#endif /* !HAVE_STRUCT_TIMESPEC */

#ако !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
цяло nanosleep(const struct timespec *, struct timespec *);
#endif

#ifndef HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
цяло utimensat(цяло, const char *, const struct timespec[2], цяло);
#endif /* !HAVE_UTIMENSAT */

#ifndef HAVE_USLEEP
цяло usleep(unsigned цяло useconds);
#endif

#ifndef HAVE_TCGETPGRP
pid_t tcgetpgrp(цяло);
#endif

#ifndef HAVE_TCSENDBREAK
цяло tcsendbreak(цяло, цяло);
#endif

#ifndef HAVE_UNSETENV
цяло unsetenv(const char *);
#endif

#ifndef HAVE_ISBLANK
цяло	isblank(цяло);
#endif

#ifndef HAVE_GETPGID
pid_t getpgid(pid_t);
#endif

#ifndef HAVE_PSELECT
цяло pselect(цяло, fd_set *, fd_set *, fd_set *, const struct timespec *,
    const sigset_t *);
#endif

#ifndef HAVE_ENDGRENT
# define endgrent() do { } докато(0)
#endif

#ifndef HAVE_KRB5_GET_ERROR_MESSAGE
# define krb5_get_error_message krb5_get_err_text
#endif

#ifndef HAVE_KRB5_FREE_ERROR_MESSAGE
# define krb5_free_error_message(a,b) do { } докато(0)
#endif

#ifndef HAVE_PLEDGE
цяло pledge(const char *promises, const char *execpromises);
#endif

#ifndef HAVE_UNVEIL
цяло unveil(const char *, const char *);
#endif

/* bsd-err.h */
#ifndef HAVE_ERR
void err(цяло, const char *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_ERRX
void errx(цяло, const char *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_WARN
void warn(const char *, ...) __attribute__((format(printf, 1, 2)));
#endif

#ifndef HAVE_LLABS
long long llabs(long long);
#endif

#ако defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
void bzero(void *, size_t);
#endif

#ifndef HAVE_RAISE
цяло raise(цяло);
#endif

#ifndef HAVE_GETSID
pid_t getsid(pid_t);
#endif

#ifndef HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
цяло flock(цяло, цяло);
#endif

#ifdef FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#endif

#ifndef HAVE_LOCALTIME_R
struct tm *localtime_r(const time_t *, struct tm *);
#endif

#ifndef HAVE_CLOCK_GETTIME
typedef цяло clockid_t;
#ifndef CLOCK_REALTIME
# define CLOCK_REALTIME	0
#endif
цяло clock_gettime(clockid_t, struct timespec *);
#endif

#ifndef HAVE_REALPATH
#define realpath(x, y)	(sftp_realpath((x), (y)))
#endif

#endif /* _BSD_MISC_H */
