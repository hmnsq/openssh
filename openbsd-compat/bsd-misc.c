
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
#иначе
	ако (argv0 == NULL)
		върни ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	ако (p == NULL)
		p = argv0;
	иначе
		p++;
#endif
	ако ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	върни q;
}

#ifndef HAVE_SETLOGIN
цяло setlogin(const char *name)
{
	върни (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
цяло innetgr(const char *netgroup, const char *host,
	    const char *user, const char *domain)
{
	върни (0);
}
#endif /* HAVE_INNETGR */

#ако !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
цяло seteuid(uid_t euid)
{
	върни (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ако !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
цяло setegid(uid_t egid)
{
	върни(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ако !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const char *strerror(цяло e)
{
	extern цяло sys_nerr;
	extern char *sys_errlist[];

	ако ((e >= 0) && (e < sys_nerr))
		върни (sys_errlist[e]);

	върни ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
цяло utimes(const char *filename, struct timeval *tvp)
{
	struct utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	върни (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
цяло
utimensat(цяло fd, const char *path, const struct timespec times[2],
    цяло flag)
{
	struct timeval tv[2];
# ifdef HAVE_FUTIMES
	цяло ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	ако (fd != AT_FDCWD) {
		errno = ENOSYS;
		върни -1;
	}
# ifndef HAVE_FUTIMES
	върни utimes(path, tv);
# иначе
#  ifdef O_NOFOLLOW
	ако (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ако ((fd = open(path, oflags)) == -1)
		върни -1;
	ret = futimes(fd, tv);
	close(fd);
	върни ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
цяло
dirfd(void *dir)
{
	errno = ENOSYS;
	върни -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
цяло
fchownat(цяло fd, const char *path, uid_t owner, gid_t group, цяло flag)
{
	цяло ret, oflags = O_WRONLY;

	ако (fd != AT_FDCWD) {
		errno = ENOSYS;
		върни -1;
	}
# ifndef HAVE_FCHOWN
	върни chown(path, owner, group);
# иначе
#  ifdef O_NOFOLLOW
	ако (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ако ((fd = open(path, oflags)) == -1)
		върни -1;
	ret = fchown(fd, owner, group);
	close(fd);
	върни ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
цяло
fchmodat(цяло fd, const char *path, mode_t mode, цяло flag)
{
	цяло ret, oflags = O_WRONLY;

	ако (fd != AT_FDCWD) {
		errno = ENOSYS;
		върни -1;
	}
# ifndef HAVE_FCHMOD
	върни chmod(path, mode);
# иначе
#  ifdef O_NOFOLLOW
	ако (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ако ((fd = open(path, oflags)) == -1)
		върни -1;
	ret = fchmod(fd, mode);
	close(fd);
	върни ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
цяло
fstatat(цяло dirfd, const char *path, struct stat *sb, цяло flag)
{
	ако (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		върни -1;
	}
	ако (flag == 0)
		върни stat(path, sb);
	иначе ако (flag == AT_SYMLINK_NOFOLLOW)
		върни lstat(path, sb);
	errno = ENOSYS;
	върни -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
цяло
unlinkat(цяло dirfd, const char *path, цяло flag)
{
	ако (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		върни -1;
	}
	ако (flag == 0)
		върни unlink(path);
	errno = ENOSYS;
	върни -1;
}
#endif

#ifndef HAVE_TRUNCATE
цяло truncate(const char *path, off_t length)
{
	цяло fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	ако (fd < 0)
		върни (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	ако (ret == -1)
		errno = saverrno;

	върни(ret);
}
#endif /* HAVE_TRUNCATE */

#ако !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
цяло nanosleep(const struct timespec *req, struct timespec *rem)
{
	цяло rc, saverrno;
	extern цяло errno;
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
	} иначе {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	ако (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	върни(rc);
}
#endif

#ако !defined(HAVE_USLEEP)
цяло usleep(unsigned цяло useconds)
{
	struct timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	върни nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(цяло fd)
{
	цяло ctty_pgrp;

	ако (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		върни(-1);
	иначе
		върни(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
цяло
tcsendbreak(цяло fd, цяло duration)
{
# ако defined(TIOCSBRK) && defined(TIOCCBRK)
	struct timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	ако (ioctl(fd, TIOCSBRK, 0) == -1)
		върни (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	ако (ioctl(fd, TIOCCBRK, 0) == -1)
		върни (-1);
	върни (0);
# иначе
	върни -1;
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
		върни(memcpy(cp, str, len));
	върни NULL;
}
#endif

#ifndef HAVE_ISBLANK
цяло
isblank(цяло c)
{
	върни (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#ако defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	върни getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	ако (pid == 0)
		върни getpgrp();
#endif

	errno = ESRCH;
	върни -1;
}
#endif

#ifndef HAVE_PLEDGE
цяло
pledge(const char *promises, const char *execpromises)
{
	върни 0;
}
#endif

#ifndef HAVE_UNVEIL
цяло
unveil(const char *path, const char *permissions)
{
	върни 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
цяло
mbtowc(wchar_t *pwc, const char *s, size_t n)
{
	ако (s == NULL || *s == '\0')
		върни 0;	/* ASCII is not state-dependent */
	ако (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		върни -1;
	}
	ако (pwc != NULL)
		*pwc = *s;
	върни 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	върни (j < 0 ? -j : j);
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
цяло
raise(цяло sig)
{
	върни kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	върни -1;
}
#endif

#ifndef HAVE_KILLPG
цяло
killpg(pid_t pgrp, цяло sig)
{
	върни kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
цяло _ssh_compat_fflush(FILE *f)
{
	цяло r1, r2;

	ако (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		ако (r1 == -1 || r2 == -1)
			върни -1;
		върни 0;
	}
	върни fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
struct tm *
localtime_r(const time_t *timep, struct tm *result)
{
	struct tm *tm = localtime(timep);
	*result = *tm;
	върни result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
цяло
clock_gettime(clockid_t clockid, struct timespec *ts)
{
	struct timeval tv;

	ако (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		върни -1;
	}
	ако (ts == NULL) {
		errno = EFAULT;
		върни -1;
	}

	ако (gettimeofday(&tv, NULL) == -1)
		върни -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	върни 0;
}
#endif

#ifdef ASAN_OPTIONS
const char *__asan_default_options(void) {
	върни ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const char *__msan_default_options(void) {
	върни MSAN_OPTIONS;
}
#endif
