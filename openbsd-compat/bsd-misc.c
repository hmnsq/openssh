
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
#інакше
	якщо (argv0 == NULL)
		повернути ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	якщо (p == NULL)
		p = argv0;
	інакше
		p++;
#endif
	якщо ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	повернути q;
}

#ifndef HAVE_SETLOGIN
ціле setlogin(const char *name)
{
	повернути (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
ціле innetgr(const char *netgroup, const char *host,
	    const char *user, const char *domain)
{
	повернути (0);
}
#endif /* HAVE_INNETGR */

#якщо !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
ціле seteuid(uid_t euid)
{
	повернути (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#якщо !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
ціле setegid(uid_t egid)
{
	повернути(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#якщо !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const char *strerror(ціле e)
{
	extern ціле sys_nerr;
	extern char *sys_errlist[];

	якщо ((e >= 0) && (e < sys_nerr))
		повернути (sys_errlist[e]);

	повернути ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
ціле utimes(const char *filename, struct timeval *tvp)
{
	struct utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	повернути (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ціле
utimensat(ціле fd, const char *path, const struct timespec times[2],
    ціле flag)
{
	struct timeval tv[2];
# ifdef HAVE_FUTIMES
	ціле ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	якщо (fd != AT_FDCWD) {
		errno = ENOSYS;
		повернути -1;
	}
# ifndef HAVE_FUTIMES
	повернути utimes(path, tv);
# інакше
#  ifdef O_NOFOLLOW
	якщо (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	якщо ((fd = open(path, oflags)) == -1)
		повернути -1;
	ret = futimes(fd, tv);
	close(fd);
	повернути ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
ціле
dirfd(void *dir)
{
	errno = ENOSYS;
	повернути -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ціле
fchownat(ціле fd, const char *path, uid_t owner, gid_t group, ціле flag)
{
	ціле ret, oflags = O_WRONLY;

	якщо (fd != AT_FDCWD) {
		errno = ENOSYS;
		повернути -1;
	}
# ifndef HAVE_FCHOWN
	повернути chown(path, owner, group);
# інакше
#  ifdef O_NOFOLLOW
	якщо (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	якщо ((fd = open(path, oflags)) == -1)
		повернути -1;
	ret = fchown(fd, owner, group);
	close(fd);
	повернути ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ціле
fchmodat(ціле fd, const char *path, mode_t mode, ціле flag)
{
	ціле ret, oflags = O_WRONLY;

	якщо (fd != AT_FDCWD) {
		errno = ENOSYS;
		повернути -1;
	}
# ifndef HAVE_FCHMOD
	повернути chmod(path, mode);
# інакше
#  ifdef O_NOFOLLOW
	якщо (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	якщо ((fd = open(path, oflags)) == -1)
		повернути -1;
	ret = fchmod(fd, mode);
	close(fd);
	повернути ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
ціле
fstatat(ціле dirfd, const char *path, struct stat *sb, ціле flag)
{
	якщо (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		повернути -1;
	}
	якщо (flag == 0)
		повернути stat(path, sb);
	інакше якщо (flag == AT_SYMLINK_NOFOLLOW)
		повернути lstat(path, sb);
	errno = ENOSYS;
	повернути -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
ціле
unlinkat(ціле dirfd, const char *path, ціле flag)
{
	якщо (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		повернути -1;
	}
	якщо (flag == 0)
		повернути unlink(path);
	errno = ENOSYS;
	повернути -1;
}
#endif

#ifndef HAVE_TRUNCATE
ціле truncate(const char *path, off_t length)
{
	ціле fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	якщо (fd < 0)
		повернути (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	якщо (ret == -1)
		errno = saverrno;

	повернути(ret);
}
#endif /* HAVE_TRUNCATE */

#якщо !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
ціле nanosleep(const struct timespec *req, struct timespec *rem)
{
	ціле rc, saverrno;
	extern ціле errno;
	struct timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	якщо (rc == -1) {
		saverrno = errno;
		(void) gettimeofday (&tstop, NULL);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} інакше {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	якщо (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	повернути(rc);
}
#endif

#якщо !defined(HAVE_USLEEP)
ціле usleep(unsigned ціле useconds)
{
	struct timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	повернути nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(ціле fd)
{
	ціле ctty_pgrp;

	якщо (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		повернути(-1);
	інакше
		повернути(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
ціле
tcsendbreak(ціле fd, ціле duration)
{
# якщо defined(TIOCSBRK) && defined(TIOCCBRK)
	struct timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	якщо (ioctl(fd, TIOCSBRK, 0) == -1)
		повернути (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	якщо (ioctl(fd, TIOCCBRK, 0) == -1)
		повернути (-1);
	повернути (0);
# інакше
	повернути -1;
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
	якщо (cp != NULL)
		повернути(memcpy(cp, str, len));
	повернути NULL;
}
#endif

#ifndef HAVE_ISBLANK
ціле
isblank(ціле c)
{
	повернути (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#якщо defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	повернути getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	якщо (pid == 0)
		повернути getpgrp();
#endif

	errno = ESRCH;
	повернути -1;
}
#endif

#ifndef HAVE_PLEDGE
ціле
pledge(const char *promises, const char *execpromises)
{
	повернути 0;
}
#endif

#ifndef HAVE_UNVEIL
ціле
unveil(const char *path, const char *permissions)
{
	повернути 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
ціле
mbtowc(wchar_t *pwc, const char *s, size_t n)
{
	якщо (s == NULL || *s == '\0')
		повернути 0;	/* ASCII is not state-dependent */
	якщо (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		повернути -1;
	}
	якщо (pwc != NULL)
		*pwc = *s;
	повернути 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	повернути (j < 0 ? -j : j);
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
ціле
raise(ціле sig)
{
	повернути kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	повернути -1;
}
#endif

#ifndef HAVE_KILLPG
ціле
killpg(pid_t pgrp, ціле sig)
{
	повернути kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
ціле _ssh_compat_fflush(FILE *f)
{
	ціле r1, r2;

	якщо (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		якщо (r1 == -1 || r2 == -1)
			повернути -1;
		повернути 0;
	}
	повернути fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
struct tm *
localtime_r(const time_t *timep, struct tm *result)
{
	struct tm *tm = localtime(timep);
	*result = *tm;
	повернути result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
ціле
clock_gettime(clockid_t clockid, struct timespec *ts)
{
	struct timeval tv;

	якщо (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		повернути -1;
	}
	якщо (ts == NULL) {
		errno = EFAULT;
		повернути -1;
	}

	якщо (gettimeofday(&tv, NULL) == -1)
		повернути -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	повернути 0;
}
#endif

#ifdef ASAN_OPTIONS
const char *__asan_default_options(void) {
	повернути ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const char *__msan_default_options(void) {
	повернути MSAN_OPTIONS;
}
#endif
