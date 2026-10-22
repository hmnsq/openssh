
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
#아니면
	만약 (argv0 == NULL)
		반환 ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	만약 (p == NULL)
		p = argv0;
	아니면
		p++;
#endif
	만약 ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	반환 q;
}

#ifndef HAVE_SETLOGIN
정수 setlogin(const char *name)
{
	반환 (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
정수 innetgr(const char *netgroup, const char *host,
	    const char *user, const char *domain)
{
	반환 (0);
}
#endif /* HAVE_INNETGR */

#만약 !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
정수 seteuid(uid_t euid)
{
	반환 (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#만약 !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
정수 setegid(uid_t egid)
{
	반환(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#만약 !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const char *strerror(정수 e)
{
	extern 정수 sys_nerr;
	extern char *sys_errlist[];

	만약 ((e >= 0) && (e < sys_nerr))
		반환 (sys_errlist[e]);

	반환 ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
정수 utimes(const char *filename, struct timeval *tvp)
{
	struct utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	반환 (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
정수
utimensat(정수 fd, const char *path, const struct timespec times[2],
    정수 flag)
{
	struct timeval tv[2];
# ifdef HAVE_FUTIMES
	정수 ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	만약 (fd != AT_FDCWD) {
		errno = ENOSYS;
		반환 -1;
	}
# ifndef HAVE_FUTIMES
	반환 utimes(path, tv);
# 아니면
#  ifdef O_NOFOLLOW
	만약 (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	만약 ((fd = open(path, oflags)) == -1)
		반환 -1;
	ret = futimes(fd, tv);
	close(fd);
	반환 ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
정수
dirfd(void *dir)
{
	errno = ENOSYS;
	반환 -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
정수
fchownat(정수 fd, const char *path, uid_t owner, gid_t group, 정수 flag)
{
	정수 ret, oflags = O_WRONLY;

	만약 (fd != AT_FDCWD) {
		errno = ENOSYS;
		반환 -1;
	}
# ifndef HAVE_FCHOWN
	반환 chown(path, owner, group);
# 아니면
#  ifdef O_NOFOLLOW
	만약 (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	만약 ((fd = open(path, oflags)) == -1)
		반환 -1;
	ret = fchown(fd, owner, group);
	close(fd);
	반환 ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
정수
fchmodat(정수 fd, const char *path, mode_t mode, 정수 flag)
{
	정수 ret, oflags = O_WRONLY;

	만약 (fd != AT_FDCWD) {
		errno = ENOSYS;
		반환 -1;
	}
# ifndef HAVE_FCHMOD
	반환 chmod(path, mode);
# 아니면
#  ifdef O_NOFOLLOW
	만약 (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	만약 ((fd = open(path, oflags)) == -1)
		반환 -1;
	ret = fchmod(fd, mode);
	close(fd);
	반환 ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
정수
fstatat(정수 dirfd, const char *path, struct stat *sb, 정수 flag)
{
	만약 (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		반환 -1;
	}
	만약 (flag == 0)
		반환 stat(path, sb);
	아니면 만약 (flag == AT_SYMLINK_NOFOLLOW)
		반환 lstat(path, sb);
	errno = ENOSYS;
	반환 -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
정수
unlinkat(정수 dirfd, const char *path, 정수 flag)
{
	만약 (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		반환 -1;
	}
	만약 (flag == 0)
		반환 unlink(path);
	errno = ENOSYS;
	반환 -1;
}
#endif

#ifndef HAVE_TRUNCATE
정수 truncate(const char *path, off_t length)
{
	정수 fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	만약 (fd < 0)
		반환 (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	만약 (ret == -1)
		errno = saverrno;

	반환(ret);
}
#endif /* HAVE_TRUNCATE */

#만약 !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
정수 nanosleep(const struct timespec *req, struct timespec *rem)
{
	정수 rc, saverrno;
	extern 정수 errno;
	struct timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	만약 (rc == -1) {
		saverrno = errno;
		(void) gettimeofday (&tstop, NULL);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} 아니면 {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	만약 (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	반환(rc);
}
#endif

#만약 !defined(HAVE_USLEEP)
정수 usleep(unsigned 정수 useconds)
{
	struct timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	반환 nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(정수 fd)
{
	정수 ctty_pgrp;

	만약 (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		반환(-1);
	아니면
		반환(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
정수
tcsendbreak(정수 fd, 정수 duration)
{
# 만약 defined(TIOCSBRK) && defined(TIOCCBRK)
	struct timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	만약 (ioctl(fd, TIOCSBRK, 0) == -1)
		반환 (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	만약 (ioctl(fd, TIOCCBRK, 0) == -1)
		반환 (-1);
	반환 (0);
# 아니면
	반환 -1;
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
	만약 (cp != NULL)
		반환(memcpy(cp, str, len));
	반환 NULL;
}
#endif

#ifndef HAVE_ISBLANK
정수
isblank(정수 c)
{
	반환 (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#만약 defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	반환 getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	만약 (pid == 0)
		반환 getpgrp();
#endif

	errno = ESRCH;
	반환 -1;
}
#endif

#ifndef HAVE_PLEDGE
정수
pledge(const char *promises, const char *execpromises)
{
	반환 0;
}
#endif

#ifndef HAVE_UNVEIL
정수
unveil(const char *path, const char *permissions)
{
	반환 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
정수
mbtowc(wchar_t *pwc, const char *s, size_t n)
{
	만약 (s == NULL || *s == '\0')
		반환 0;	/* ASCII is not state-dependent */
	만약 (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		반환 -1;
	}
	만약 (pwc != NULL)
		*pwc = *s;
	반환 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	반환 (j < 0 ? -j : j);
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
정수
raise(정수 sig)
{
	반환 kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	반환 -1;
}
#endif

#ifndef HAVE_KILLPG
정수
killpg(pid_t pgrp, 정수 sig)
{
	반환 kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
정수 _ssh_compat_fflush(FILE *f)
{
	정수 r1, r2;

	만약 (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		만약 (r1 == -1 || r2 == -1)
			반환 -1;
		반환 0;
	}
	반환 fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
struct tm *
localtime_r(const time_t *timep, struct tm *result)
{
	struct tm *tm = localtime(timep);
	*result = *tm;
	반환 result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
정수
clock_gettime(clockid_t clockid, struct timespec *ts)
{
	struct timeval tv;

	만약 (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		반환 -1;
	}
	만약 (ts == NULL) {
		errno = EFAULT;
		반환 -1;
	}

	만약 (gettimeofday(&tv, NULL) == -1)
		반환 -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	반환 0;
}
#endif

#ifdef ASAN_OPTIONS
const char *__asan_default_options(void) {
	반환 ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const char *__msan_default_options(void) {
	반환 MSAN_OPTIONS;
}
#endif
