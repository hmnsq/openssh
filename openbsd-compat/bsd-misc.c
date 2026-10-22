
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
#không_thì
	nếu (argv0 == NULL)
		trả_về ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	nếu (p == NULL)
		p = argv0;
	không_thì
		p++;
#endif
	nếu ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	trả_về q;
}

#ifndef HAVE_SETLOGIN
số_nguyên setlogin(const char *name)
{
	trả_về (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
số_nguyên innetgr(const char *netgroup, const char *host,
	    const char *user, const char *domain)
{
	trả_về (0);
}
#endif /* HAVE_INNETGR */

#nếu !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
số_nguyên seteuid(uid_t euid)
{
	trả_về (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#nếu !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
số_nguyên setegid(uid_t egid)
{
	trả_về(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#nếu !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const char *strerror(số_nguyên e)
{
	extern số_nguyên sys_nerr;
	extern char *sys_errlist[];

	nếu ((e >= 0) && (e < sys_nerr))
		trả_về (sys_errlist[e]);

	trả_về ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
số_nguyên utimes(const char *filename, struct timeval *tvp)
{
	struct utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	trả_về (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
số_nguyên
utimensat(số_nguyên fd, const char *path, const struct timespec times[2],
    số_nguyên flag)
{
	struct timeval tv[2];
# ifdef HAVE_FUTIMES
	số_nguyên ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	nếu (fd != AT_FDCWD) {
		errno = ENOSYS;
		trả_về -1;
	}
# ifndef HAVE_FUTIMES
	trả_về utimes(path, tv);
# không_thì
#  ifdef O_NOFOLLOW
	nếu (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	nếu ((fd = open(path, oflags)) == -1)
		trả_về -1;
	ret = futimes(fd, tv);
	close(fd);
	trả_về ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
số_nguyên
dirfd(void *dir)
{
	errno = ENOSYS;
	trả_về -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
số_nguyên
fchownat(số_nguyên fd, const char *path, uid_t owner, gid_t group, số_nguyên flag)
{
	số_nguyên ret, oflags = O_WRONLY;

	nếu (fd != AT_FDCWD) {
		errno = ENOSYS;
		trả_về -1;
	}
# ifndef HAVE_FCHOWN
	trả_về chown(path, owner, group);
# không_thì
#  ifdef O_NOFOLLOW
	nếu (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	nếu ((fd = open(path, oflags)) == -1)
		trả_về -1;
	ret = fchown(fd, owner, group);
	close(fd);
	trả_về ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
số_nguyên
fchmodat(số_nguyên fd, const char *path, mode_t mode, số_nguyên flag)
{
	số_nguyên ret, oflags = O_WRONLY;

	nếu (fd != AT_FDCWD) {
		errno = ENOSYS;
		trả_về -1;
	}
# ifndef HAVE_FCHMOD
	trả_về chmod(path, mode);
# không_thì
#  ifdef O_NOFOLLOW
	nếu (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	nếu ((fd = open(path, oflags)) == -1)
		trả_về -1;
	ret = fchmod(fd, mode);
	close(fd);
	trả_về ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
số_nguyên
fstatat(số_nguyên dirfd, const char *path, struct stat *sb, số_nguyên flag)
{
	nếu (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		trả_về -1;
	}
	nếu (flag == 0)
		trả_về stat(path, sb);
	không_thì nếu (flag == AT_SYMLINK_NOFOLLOW)
		trả_về lstat(path, sb);
	errno = ENOSYS;
	trả_về -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
số_nguyên
unlinkat(số_nguyên dirfd, const char *path, số_nguyên flag)
{
	nếu (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		trả_về -1;
	}
	nếu (flag == 0)
		trả_về unlink(path);
	errno = ENOSYS;
	trả_về -1;
}
#endif

#ifndef HAVE_TRUNCATE
số_nguyên truncate(const char *path, off_t length)
{
	số_nguyên fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	nếu (fd < 0)
		trả_về (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	nếu (ret == -1)
		errno = saverrno;

	trả_về(ret);
}
#endif /* HAVE_TRUNCATE */

#nếu !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
số_nguyên nanosleep(const struct timespec *req, struct timespec *rem)
{
	số_nguyên rc, saverrno;
	extern số_nguyên errno;
	struct timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	nếu (rc == -1) {
		saverrno = errno;
		(void) gettimeofday (&tstop, NULL);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} không_thì {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	nếu (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	trả_về(rc);
}
#endif

#nếu !defined(HAVE_USLEEP)
số_nguyên usleep(unsigned số_nguyên useconds)
{
	struct timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	trả_về nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(số_nguyên fd)
{
	số_nguyên ctty_pgrp;

	nếu (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		trả_về(-1);
	không_thì
		trả_về(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
số_nguyên
tcsendbreak(số_nguyên fd, số_nguyên duration)
{
# nếu defined(TIOCSBRK) && defined(TIOCCBRK)
	struct timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	nếu (ioctl(fd, TIOCSBRK, 0) == -1)
		trả_về (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	nếu (ioctl(fd, TIOCCBRK, 0) == -1)
		trả_về (-1);
	trả_về (0);
# không_thì
	trả_về -1;
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
	nếu (cp != NULL)
		trả_về(memcpy(cp, str, len));
	trả_về NULL;
}
#endif

#ifndef HAVE_ISBLANK
số_nguyên
isblank(số_nguyên c)
{
	trả_về (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#nếu defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	trả_về getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	nếu (pid == 0)
		trả_về getpgrp();
#endif

	errno = ESRCH;
	trả_về -1;
}
#endif

#ifndef HAVE_PLEDGE
số_nguyên
pledge(const char *promises, const char *execpromises)
{
	trả_về 0;
}
#endif

#ifndef HAVE_UNVEIL
số_nguyên
unveil(const char *path, const char *permissions)
{
	trả_về 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
số_nguyên
mbtowc(wchar_t *pwc, const char *s, size_t n)
{
	nếu (s == NULL || *s == '\0')
		trả_về 0;	/* ASCII is not state-dependent */
	nếu (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		trả_về -1;
	}
	nếu (pwc != NULL)
		*pwc = *s;
	trả_về 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	trả_về (j < 0 ? -j : j);
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
số_nguyên
raise(số_nguyên sig)
{
	trả_về kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	trả_về -1;
}
#endif

#ifndef HAVE_KILLPG
số_nguyên
killpg(pid_t pgrp, số_nguyên sig)
{
	trả_về kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
số_nguyên _ssh_compat_fflush(FILE *f)
{
	số_nguyên r1, r2;

	nếu (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		nếu (r1 == -1 || r2 == -1)
			trả_về -1;
		trả_về 0;
	}
	trả_về fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
struct tm *
localtime_r(const time_t *timep, struct tm *result)
{
	struct tm *tm = localtime(timep);
	*result = *tm;
	trả_về result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
số_nguyên
clock_gettime(clockid_t clockid, struct timespec *ts)
{
	struct timeval tv;

	nếu (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		trả_về -1;
	}
	nếu (ts == NULL) {
		errno = EFAULT;
		trả_về -1;
	}

	nếu (gettimeofday(&tv, NULL) == -1)
		trả_về -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	trả_về 0;
}
#endif

#ifdef ASAN_OPTIONS
const char *__asan_default_options(void) {
	trả_về ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const char *__msan_default_options(void) {
	trả_về MSAN_OPTIONS;
}
#endif
