
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

#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#include <sys/time.h>

#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#ifndef HAVE___PROGNAME
char *__progname;
#endif

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
char *ssh_get_progname(char *argv0)
{
	char *p, *q;
#ifdef HAVE___PROGNAME
	extern char *__progname;

	p = __progname;
#否则
	如果 (argv0 == NULL)
		返回 ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	如果 (p == NULL)
		p = argv0;
	否则
		p++;
#endif
	如果 ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	返回 q;
}

#ifndef HAVE_SETLOGIN
整数 setlogin(const char *name)
{
	返回 (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
整数 innetgr(const char *netgroup, const char *host,
	    const char *user, const char *domain)
{
	返回 (0);
}
#endif /* HAVE_INNETGR */

#如果 !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
整数 seteuid(uid_t euid)
{
	返回 (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#如果 !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
整数 setegid(uid_t egid)
{
	返回(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#如果 !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const char *strerror(整数 e)
{
	extern 整数 sys_nerr;
	extern char *sys_errlist[];

	如果 ((e >= 0) && (e < sys_nerr))
		返回 (sys_errlist[e]);

	返回 ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
整数 utimes(const char *filename, struct timeval *tvp)
{
	struct utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	返回 (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
整数
utimensat(整数 fd, const char *path, const struct timespec times[2],
    整数 flag)
{
	struct timeval tv[2];
# ifdef HAVE_FUTIMES
	整数 ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	如果 (fd != AT_FDCWD) {
		errno = ENOSYS;
		返回 -1;
	}
# ifndef HAVE_FUTIMES
	返回 utimes(path, tv);
# 否则
#  ifdef O_NOFOLLOW
	如果 (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	如果 ((fd = open(path, oflags)) == -1)
		返回 -1;
	ret = futimes(fd, tv);
	close(fd);
	返回 ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
整数
dirfd(void *dir)
{
	errno = ENOSYS;
	返回 -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
整数
fchownat(整数 fd, const char *path, uid_t owner, gid_t group, 整数 flag)
{
	整数 ret, oflags = O_WRONLY;

	如果 (fd != AT_FDCWD) {
		errno = ENOSYS;
		返回 -1;
	}
# ifndef HAVE_FCHOWN
	返回 chown(path, owner, group);
# 否则
#  ifdef O_NOFOLLOW
	如果 (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	如果 ((fd = open(path, oflags)) == -1)
		返回 -1;
	ret = fchown(fd, owner, group);
	close(fd);
	返回 ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
整数
fchmodat(整数 fd, const char *path, mode_t mode, 整数 flag)
{
	整数 ret, oflags = O_WRONLY;

	如果 (fd != AT_FDCWD) {
		errno = ENOSYS;
		返回 -1;
	}
# ifndef HAVE_FCHMOD
	返回 chmod(path, mode);
# 否则
#  ifdef O_NOFOLLOW
	如果 (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	如果 ((fd = open(path, oflags)) == -1)
		返回 -1;
	ret = fchmod(fd, mode);
	close(fd);
	返回 ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
整数
fstatat(整数 dirfd, const char *path, struct stat *sb, 整数 flag)
{
	如果 (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		返回 -1;
	}
	如果 (flag == 0)
		返回 stat(path, sb);
	否则 如果 (flag == AT_SYMLINK_NOFOLLOW)
		返回 lstat(path, sb);
	errno = ENOSYS;
	返回 -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
整数
unlinkat(整数 dirfd, const char *path, 整数 flag)
{
	如果 (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		返回 -1;
	}
	如果 (flag == 0)
		返回 unlink(path);
	errno = ENOSYS;
	返回 -1;
}
#endif

#ifndef HAVE_TRUNCATE
整数 truncate(const char *path, off_t length)
{
	整数 fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	如果 (fd < 0)
		返回 (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	如果 (ret == -1)
		errno = saverrno;

	返回(ret);
}
#endif /* HAVE_TRUNCATE */

#如果 !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
整数 nanosleep(const struct timespec *req, struct timespec *rem)
{
	整数 rc, saverrno;
	extern 整数 errno;
	struct timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	如果 (rc == -1) {
		saverrno = errno;
		(void) gettimeofday (&tstop, NULL);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} 否则 {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	如果 (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	返回(rc);
}
#endif

#如果 !defined(HAVE_USLEEP)
整数 usleep(unsigned 整数 useconds)
{
	struct timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	返回 nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(整数 fd)
{
	整数 ctty_pgrp;

	如果 (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		返回(-1);
	否则
		返回(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
整数
tcsendbreak(整数 fd, 整数 duration)
{
# 如果 defined(TIOCSBRK) && defined(TIOCCBRK)
	struct timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	如果 (ioctl(fd, TIOCSBRK, 0) == -1)
		返回 (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	如果 (ioctl(fd, TIOCCBRK, 0) == -1)
		返回 (-1);
	返回 (0);
# 否则
	返回 -1;
# endif
}
#endif /* HAVE_TCSENDBREAK */

#ifndef HAVE_STRDUP
char *
strdup(const char *str)
{
	size_t len;
	char *cp;

	len = strlen(str) + 1;
	cp = malloc(len);
	如果 (cp != NULL)
		返回(memcpy(cp, str, len));
	返回 NULL;
}
#endif

#ifndef HAVE_ISBLANK
整数
isblank(整数 c)
{
	返回 (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#如果 defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	返回 getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	如果 (pid == 0)
		返回 getpgrp();
#endif

	errno = ESRCH;
	返回 -1;
}
#endif

#ifndef HAVE_PLEDGE
整数
pledge(const char *promises, const char *execpromises)
{
	返回 0;
}
#endif

#ifndef HAVE_UNVEIL
整数
unveil(const char *path, const char *permissions)
{
	返回 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
整数
mbtowc(wchar_t *pwc, const char *s, size_t n)
{
	如果 (s == NULL || *s == '\0')
		返回 0;	/* ASCII is not state-dependent */
	如果 (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		返回 -1;
	}
	如果 (pwc != NULL)
		*pwc = *s;
	返回 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	返回 (j < 0 ? -j : j);
}
#endif

#ifndef HAVE_BZERO
void
bzero(void *b, size_t n)
{
	(void)memset(b, 0, n);
}
#endif

#ifndef HAVE_RAISE
整数
raise(整数 sig)
{
	返回 kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	返回 -1;
}
#endif

#ifndef HAVE_KILLPG
整数
killpg(pid_t pgrp, 整数 sig)
{
	返回 kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
整数 _ssh_compat_fflush(FILE *f)
{
	整数 r1, r2;

	如果 (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		如果 (r1 == -1 || r2 == -1)
			返回 -1;
		返回 0;
	}
	返回 fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
struct tm *
localtime_r(const time_t *timep, struct tm *result)
{
	struct tm *tm = localtime(timep);
	*result = *tm;
	返回 result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
整数
clock_gettime(clockid_t clockid, struct timespec *ts)
{
	struct timeval tv;

	如果 (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		返回 -1;
	}
	如果 (ts == NULL) {
		errno = EFAULT;
		返回 -1;
	}

	如果 (gettimeofday(&tv, NULL) == -1)
		返回 -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	返回 0;
}
#endif

#ifdef ASAN_OPTIONS
const char *__asan_default_options(void) {
	返回 ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const char *__msan_default_options(void) {
	返回 MSAN_OPTIONS;
}
#endif
