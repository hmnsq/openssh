
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
#инако
	ако (argv0 == NULL)
		врати ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	ако (p == NULL)
		p = argv0;
	инако
		p++;
#endif
	ако ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	врати q;
}

#ifndef HAVE_SETLOGIN
цео setlogin(const char *name)
{
	врати (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
цео innetgr(const char *netgroup, const char *host,
	    const char *user, const char *domain)
{
	врати (0);
}
#endif /* HAVE_INNETGR */

#ако !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
цео seteuid(uid_t euid)
{
	врати (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ако !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
цео setegid(uid_t egid)
{
	врати(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ако !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const char *strerror(цео e)
{
	extern цео sys_nerr;
	extern char *sys_errlist[];

	ако ((e >= 0) && (e < sys_nerr))
		врати (sys_errlist[e]);

	врати ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
цео utimes(const char *filename, struct timeval *tvp)
{
	struct utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	врати (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
цео
utimensat(цео fd, const char *path, const struct timespec times[2],
    цео flag)
{
	struct timeval tv[2];
# ifdef HAVE_FUTIMES
	цео ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	ако (fd != AT_FDCWD) {
		errno = ENOSYS;
		врати -1;
	}
# ifndef HAVE_FUTIMES
	врати utimes(path, tv);
# инако
#  ifdef O_NOFOLLOW
	ако (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ако ((fd = open(path, oflags)) == -1)
		врати -1;
	ret = futimes(fd, tv);
	close(fd);
	врати ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
цео
dirfd(void *dir)
{
	errno = ENOSYS;
	врати -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
цео
fchownat(цео fd, const char *path, uid_t owner, gid_t group, цео flag)
{
	цео ret, oflags = O_WRONLY;

	ако (fd != AT_FDCWD) {
		errno = ENOSYS;
		врати -1;
	}
# ifndef HAVE_FCHOWN
	врати chown(path, owner, group);
# инако
#  ifdef O_NOFOLLOW
	ако (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ако ((fd = open(path, oflags)) == -1)
		врати -1;
	ret = fchown(fd, owner, group);
	close(fd);
	врати ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
цео
fchmodat(цео fd, const char *path, mode_t mode, цео flag)
{
	цео ret, oflags = O_WRONLY;

	ако (fd != AT_FDCWD) {
		errno = ENOSYS;
		врати -1;
	}
# ifndef HAVE_FCHMOD
	врати chmod(path, mode);
# инако
#  ifdef O_NOFOLLOW
	ако (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ако ((fd = open(path, oflags)) == -1)
		врати -1;
	ret = fchmod(fd, mode);
	close(fd);
	врати ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
цео
fstatat(цео dirfd, const char *path, struct stat *sb, цео flag)
{
	ако (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		врати -1;
	}
	ако (flag == 0)
		врати stat(path, sb);
	инако ако (flag == AT_SYMLINK_NOFOLLOW)
		врати lstat(path, sb);
	errno = ENOSYS;
	врати -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
цео
unlinkat(цео dirfd, const char *path, цео flag)
{
	ако (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		врати -1;
	}
	ако (flag == 0)
		врати unlink(path);
	errno = ENOSYS;
	врати -1;
}
#endif

#ifndef HAVE_TRUNCATE
цео truncate(const char *path, off_t length)
{
	цео fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	ако (fd < 0)
		врати (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	ако (ret == -1)
		errno = saverrno;

	врати(ret);
}
#endif /* HAVE_TRUNCATE */

#ако !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
цео nanosleep(const struct timespec *req, struct timespec *rem)
{
	цео rc, saverrno;
	extern цео errno;
	struct timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	ако (rc == -1) {
		saverrno = errno;
		(void) gettimeofday (&tstop, NULL);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} инако {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	ако (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	врати(rc);
}
#endif

#ако !defined(HAVE_USLEEP)
цео usleep(unsigned цео useconds)
{
	struct timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	врати nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(цео fd)
{
	цео ctty_pgrp;

	ако (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		врати(-1);
	инако
		врати(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
цео
tcsendbreak(цео fd, цео duration)
{
# ако defined(TIOCSBRK) && defined(TIOCCBRK)
	struct timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	ако (ioctl(fd, TIOCSBRK, 0) == -1)
		врати (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	ако (ioctl(fd, TIOCCBRK, 0) == -1)
		врати (-1);
	врати (0);
# инако
	врати -1;
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
	ако (cp != NULL)
		врати(memcpy(cp, str, len));
	врати NULL;
}
#endif

#ifndef HAVE_ISBLANK
цео
isblank(цео c)
{
	врати (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#ако defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	врати getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	ако (pid == 0)
		врати getpgrp();
#endif

	errno = ESRCH;
	врати -1;
}
#endif

#ifndef HAVE_PLEDGE
цео
pledge(const char *promises, const char *execpromises)
{
	врати 0;
}
#endif

#ifndef HAVE_UNVEIL
цео
unveil(const char *path, const char *permissions)
{
	врати 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
цео
mbtowc(wchar_t *pwc, const char *s, size_t n)
{
	ако (s == NULL || *s == '\0')
		врати 0;	/* ASCII is not state-dependent */
	ако (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		врати -1;
	}
	ако (pwc != NULL)
		*pwc = *s;
	врати 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	врати (j < 0 ? -j : j);
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
цео
raise(цео sig)
{
	врати kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	врати -1;
}
#endif

#ifndef HAVE_KILLPG
цео
killpg(pid_t pgrp, цео sig)
{
	врати kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
цео _ssh_compat_fflush(FILE *f)
{
	цео r1, r2;

	ако (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		ако (r1 == -1 || r2 == -1)
			врати -1;
		врати 0;
	}
	врати fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
struct tm *
localtime_r(const time_t *timep, struct tm *result)
{
	struct tm *tm = localtime(timep);
	*result = *tm;
	врати result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
цео
clock_gettime(clockid_t clockid, struct timespec *ts)
{
	struct timeval tv;

	ако (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		врати -1;
	}
	ако (ts == NULL) {
		errno = EFAULT;
		врати -1;
	}

	ако (gettimeofday(&tv, NULL) == -1)
		врати -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	врати 0;
}
#endif

#ifdef ASAN_OPTIONS
const char *__asan_default_options(void) {
	врати ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const char *__msan_default_options(void) {
	врати MSAN_OPTIONS;
}
#endif
