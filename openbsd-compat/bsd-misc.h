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
ціле seed_from_prngd(unsigned char *, size_t);

#ifndef HAVE_SETSID
#define setsid() setpgrp(0, getpid())
#endif /* !HAVE_SETSID */

#ifndef HAVE_SETENV
ціле setenv(const char *, const char *, ціле);
#endif /* !HAVE_SETENV */

#ifndef HAVE_SETLOGIN
ціле setlogin(const char *);
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
ціле innetgr(const char *, const char *, const char *, const char *);
#endif /* HAVE_INNETGR */

#якщо !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
ціле seteuid(uid_t);
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#якщо !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
ціле setegid(uid_t);
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#якщо !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const char *strerror(ціле);
#endif

#якщо !defined(HAVE_SETLINEBUF)
#define setlinebuf(a)	(setvbuf((a), NULL, _IOLBF, 0))
#endif

#ifndef HAVE_UTIMES
#ifndef HAVE_STRUCT_TIMEVAL
struct timeval {
	long tv_sec;
	long tv_usec;
}
#endif /* HAVE_STRUCT_TIMEVAL */

ціле utimes(const char *, struct timeval *);
#endif /* HAVE_UTIMES */

#ifndef HAVE_DIRFD
ціле dirfd(void *);
#endif

#ifndef AT_FDCWD
# define AT_FDCWD (-2)
#endif

#ifndef HAVE_FCHMODAT
ціле fchmodat(ціле, const char *, mode_t, ціле);
#endif

#ifndef HAVE_FCHOWNAT
ціле fchownat(ціле, const char *, uid_t, gid_t, ціле);
#endif

#ifdef HAVE_FSTATAT
ціле fstatat(ціле, const char *, struct stat *, ціле);
#endif

#ifdef HAVE_UNLINKAT
ціле unlinkat(ціле, const char *, ціле);
#endif

#ifndef HAVE_TRUNCATE
ціле truncate (const char *, off_t);
#endif /* HAVE_TRUNCATE */

#ifndef HAVE_STRUCT_TIMESPEC
struct timespec {
	time_t	tv_sec;
	long	tv_nsec;
};
#endif /* !HAVE_STRUCT_TIMESPEC */

#якщо !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
ціле nanosleep(const struct timespec *, struct timespec *);
#endif

#ifndef HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
ціле utimensat(ціле, const char *, const struct timespec[2], ціле);
#endif /* !HAVE_UTIMENSAT */

#ifndef HAVE_USLEEP
ціле usleep(unsigned ціле useconds);
#endif

#ifndef HAVE_TCGETPGRP
pid_t tcgetpgrp(ціле);
#endif

#ifndef HAVE_TCSENDBREAK
ціле tcsendbreak(ціле, ціле);
#endif

#ifndef HAVE_UNSETENV
ціле unsetenv(const char *);
#endif

#ifndef HAVE_ISBLANK
ціле	isblank(ціле);
#endif

#ifndef HAVE_GETPGID
pid_t getpgid(pid_t);
#endif

#ifndef HAVE_PSELECT
ціле pselect(ціле, fd_set *, fd_set *, fd_set *, const struct timespec *,
    const sigset_t *);
#endif

#ifndef HAVE_ENDGRENT
# define endgrent() do { } поки(0)
#endif

#ifndef HAVE_KRB5_GET_ERROR_MESSAGE
# define krb5_get_error_message krb5_get_err_text
#endif

#ifndef HAVE_KRB5_FREE_ERROR_MESSAGE
# define krb5_free_error_message(a,b) do { } поки(0)
#endif

#ifndef HAVE_PLEDGE
ціле pledge(const char *promises, const char *execpromises);
#endif

#ifndef HAVE_UNVEIL
ціле unveil(const char *, const char *);
#endif

/* bsd-err.h */
#ifndef HAVE_ERR
void err(ціле, const char *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_ERRX
void errx(ціле, const char *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_WARN
void warn(const char *, ...) __attribute__((format(printf, 1, 2)));
#endif

#ifndef HAVE_LLABS
long long llabs(long long);
#endif

#якщо defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
void bzero(void *, size_t);
#endif

#ifndef HAVE_RAISE
ціле raise(ціле);
#endif

#ifndef HAVE_GETSID
pid_t getsid(pid_t);
#endif

#ifndef HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
ціле flock(ціле, ціле);
#endif

#ifdef FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#endif

#ifndef HAVE_LOCALTIME_R
struct tm *localtime_r(const time_t *, struct tm *);
#endif

#ifndef HAVE_CLOCK_GETTIME
typedef ціле clockid_t;
#ifndef CLOCK_REALTIME
# define CLOCK_REALTIME	0
#endif
ціле clock_gettime(clockid_t, struct timespec *);
#endif

#ifndef HAVE_REALPATH
#define realpath(x, y)	(sftp_realpath((x), (y)))
#endif

#endif /* _BSD_MISC_H */
