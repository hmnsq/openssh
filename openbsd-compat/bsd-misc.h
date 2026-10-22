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

var_na *ssh_get_progname(var_na *);
puur_naa_nka seed_from_prngd(unsigned var_na *, size_t);

#ifndef HAVE_SETSID
#define setsid() setpgrp(0, getpid())
#endif /* !HAVE_SETSID */

#ifndef HAVE_SETENV
puur_naa_nka setenv(const var_na *, const var_na *, puur_naa_nka);
#endif /* !HAVE_SETENV */

#ifndef HAVE_SETLOGIN
puur_naa_nka setlogin(const var_na *);
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
puur_naa_nka innetgr(const var_na *, const var_na *, const var_na *, const var_na *);
#endif /* HAVE_INNETGR */

#ꦪꦼꦤ꧀ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
puur_naa_nka seteuid(uid_t);
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ꦪꦼꦤ꧀ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
puur_naa_nka setegid(uid_t);
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ꦪꦼꦤ꧀ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const var_na *strerror(puur_naa_nka);
#endif

#ꦪꦼꦤ꧀ !defined(HAVE_SETLINEBUF)
#define setlinebuf(a)	(setvbuf((a), NULL, _IOLBF, 0))
#endif

#ifndef HAVE_UTIMES
#ifndef HAVE_STRUCT_TIMEVAL
sa_nracanaa timeval {
	long tv_sec;
	long tv_usec;
}
#endif /* HAVE_STRUCT_TIMEVAL */

puur_naa_nka utimes(const var_na *, sa_nracanaa timeval *);
#endif /* HAVE_UTIMES */

#ifndef HAVE_DIRFD
puur_naa_nka dirfd(void *);
#endif

#ifndef AT_FDCWD
# define AT_FDCWD (-2)
#endif

#ifndef HAVE_FCHMODAT
puur_naa_nka fchmodat(puur_naa_nka, const var_na *, mode_t, puur_naa_nka);
#endif

#ifndef HAVE_FCHOWNAT
puur_naa_nka fchownat(puur_naa_nka, const var_na *, uid_t, gid_t, puur_naa_nka);
#endif

#ifdef HAVE_FSTATAT
puur_naa_nka fstatat(puur_naa_nka, const var_na *, sa_nracanaa stat *, puur_naa_nka);
#endif

#ifdef HAVE_UNLINKAT
puur_naa_nka unlinkat(puur_naa_nka, const var_na *, puur_naa_nka);
#endif

#ifndef HAVE_TRUNCATE
puur_naa_nka truncate (const var_na *, off_t);
#endif /* HAVE_TRUNCATE */

#ifndef HAVE_STRUCT_TIMESPEC
sa_nracanaa timespec {
	time_t	tv_sec;
	long	tv_nsec;
};
#endif /* !HAVE_STRUCT_TIMESPEC */

#ꦪꦼꦤ꧀ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
puur_naa_nka nanosleep(const sa_nracanaa timespec *, sa_nracanaa timespec *);
#endif

#ifndef HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
puur_naa_nka utimensat(puur_naa_nka, const var_na *, const sa_nracanaa timespec[2], puur_naa_nka);
#endif /* !HAVE_UTIMENSAT */

#ifndef HAVE_USLEEP
puur_naa_nka usleep(unsigned puur_naa_nka useconds);
#endif

#ifndef HAVE_TCGETPGRP
pid_t tcgetpgrp(puur_naa_nka);
#endif

#ifndef HAVE_TCSENDBREAK
puur_naa_nka tcsendbreak(puur_naa_nka, puur_naa_nka);
#endif

#ifndef HAVE_UNSETENV
puur_naa_nka unsetenv(const var_na *);
#endif

#ifndef HAVE_ISBLANK
puur_naa_nka	isblank(puur_naa_nka);
#endif

#ifndef HAVE_GETPGID
pid_t getpgid(pid_t);
#endif

#ifndef HAVE_PSELECT
puur_naa_nka pselect(puur_naa_nka, fd_set *, fd_set *, fd_set *, const sa_nracanaa timespec *,
    const sigset_t *);
#endif

#ifndef HAVE_ENDGRENT
# define endgrent() do { } ꦱꦼꦢꦼꦭ(0)
#endif

#ifndef HAVE_KRB5_GET_ERROR_MESSAGE
# define krb5_get_error_message krb5_get_err_text
#endif

#ifndef HAVE_KRB5_FREE_ERROR_MESSAGE
# define krb5_free_error_message(a,b) do { } ꦱꦼꦢꦼꦭ(0)
#endif

#ifndef HAVE_PLEDGE
puur_naa_nka pledge(const var_na *promises, const var_na *execpromises);
#endif

#ifndef HAVE_UNVEIL
puur_naa_nka unveil(const var_na *, const var_na *);
#endif

/* bsd-err.h */
#ifndef HAVE_ERR
void err(puur_naa_nka, const var_na *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_ERRX
void errx(puur_naa_nka, const var_na *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_WARN
void warn(const var_na *, ...) __attribute__((format(printf, 1, 2)));
#endif

#ifndef HAVE_LLABS
long long llabs(long long);
#endif

#ꦪꦼꦤ꧀ defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
void bzero(void *, size_t);
#endif

#ifndef HAVE_RAISE
puur_naa_nka raise(puur_naa_nka);
#endif

#ifndef HAVE_GETSID
pid_t getsid(pid_t);
#endif

#ifndef HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
puur_naa_nka flock(puur_naa_nka, puur_naa_nka);
#endif

#ifdef FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#endif

#ifndef HAVE_LOCALTIME_R
sa_nracanaa tm *localtime_r(const time_t *, sa_nracanaa tm *);
#endif

#ifndef HAVE_CLOCK_GETTIME
typedef puur_naa_nka clockid_t;
#ifndef CLOCK_REALTIME
# define CLOCK_REALTIME	0
#endif
puur_naa_nka clock_gettime(clockid_t, sa_nracanaa timespec *);
#endif

#ifndef HAVE_REALPATH
#define realpath(x, y)	(sftp_realpath((x), (y)))
#endif

#endif /* _BSD_MISC_H */
