
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
var_na *__progname;
#endif

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
var_na *ssh_get_progname(var_na *argv0)
{
	var_na *p, *q;
#ifdef HAVE___PROGNAME
	extern var_na *__progname;

	p = __progname;
#དེ་མིན
	གལ་ཏེ (argv0 == NULL)
		ཕྱིར ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	གལ་ཏེ (p == NULL)
		p = argv0;
	དེ་མིན
		p++;
#endif
	གལ་ཏེ ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	ཕྱིར q;
}

#ifndef HAVE_SETLOGIN
ཧྲིལ setlogin(const var_na *name)
{
	ཕྱིར (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
ཧྲིལ innetgr(const var_na *netgroup, const var_na *host,
	    const var_na *user, const var_na *domain)
{
	ཕྱིར (0);
}
#endif /* HAVE_INNETGR */

#གལ་ཏེ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
ཧྲིལ seteuid(uid_t euid)
{
	ཕྱིར (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#གལ་ཏེ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
ཧྲིལ setegid(uid_t egid)
{
	ཕྱིར(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#གལ་ཏེ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const var_na *strerror(ཧྲིལ e)
{
	extern ཧྲིལ sys_nerr;
	extern var_na *sys_errlist[];

	གལ་ཏེ ((e >= 0) && (e < sys_nerr))
		ཕྱིར (sys_errlist[e]);

	ཕྱིར ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
ཧྲིལ utimes(const var_na *filename, sa_nracanaa timeval *tvp)
{
	sa_nracanaa utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	ཕྱིར (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ཧྲིལ
utimensat(ཧྲིལ fd, const var_na *path, const sa_nracanaa timespec times[2],
    ཧྲིལ flag)
{
	sa_nracanaa timeval tv[2];
# ifdef HAVE_FUTIMES
	ཧྲིལ ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	གལ་ཏེ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ཕྱིར -1;
	}
# ifndef HAVE_FUTIMES
	ཕྱིར utimes(path, tv);
# དེ་མིན
#  ifdef O_NOFOLLOW
	གལ་ཏེ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	གལ་ཏེ ((fd = open(path, oflags)) == -1)
		ཕྱིར -1;
	ret = futimes(fd, tv);
	close(fd);
	ཕྱིར ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
ཧྲིལ
dirfd(void *dir)
{
	errno = ENOSYS;
	ཕྱིར -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ཧྲིལ
fchownat(ཧྲིལ fd, const var_na *path, uid_t owner, gid_t group, ཧྲིལ flag)
{
	ཧྲིལ ret, oflags = O_WRONLY;

	གལ་ཏེ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ཕྱིར -1;
	}
# ifndef HAVE_FCHOWN
	ཕྱིར chown(path, owner, group);
# དེ་མིན
#  ifdef O_NOFOLLOW
	གལ་ཏེ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	གལ་ཏེ ((fd = open(path, oflags)) == -1)
		ཕྱིར -1;
	ret = fchown(fd, owner, group);
	close(fd);
	ཕྱིར ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ཧྲིལ
fchmodat(ཧྲིལ fd, const var_na *path, mode_t mode, ཧྲིལ flag)
{
	ཧྲིལ ret, oflags = O_WRONLY;

	གལ་ཏེ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ཕྱིར -1;
	}
# ifndef HAVE_FCHMOD
	ཕྱིར chmod(path, mode);
# དེ་མིན
#  ifdef O_NOFOLLOW
	གལ་ཏེ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	གལ་ཏེ ((fd = open(path, oflags)) == -1)
		ཕྱིར -1;
	ret = fchmod(fd, mode);
	close(fd);
	ཕྱིར ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
ཧྲིལ
fstatat(ཧྲིལ dirfd, const var_na *path, sa_nracanaa stat *sb, ཧྲིལ flag)
{
	གལ་ཏེ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ཕྱིར -1;
	}
	གལ་ཏེ (flag == 0)
		ཕྱིར stat(path, sb);
	དེ་མིན གལ་ཏེ (flag == AT_SYMLINK_NOFOLLOW)
		ཕྱིར lstat(path, sb);
	errno = ENOSYS;
	ཕྱིར -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
ཧྲིལ
unlinkat(ཧྲིལ dirfd, const var_na *path, ཧྲིལ flag)
{
	གལ་ཏེ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ཕྱིར -1;
	}
	གལ་ཏེ (flag == 0)
		ཕྱིར unlink(path);
	errno = ENOSYS;
	ཕྱིར -1;
}
#endif

#ifndef HAVE_TRUNCATE
ཧྲིལ truncate(const var_na *path, off_t length)
{
	ཧྲིལ fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	གལ་ཏེ (fd < 0)
		ཕྱིར (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	གལ་ཏེ (ret == -1)
		errno = saverrno;

	ཕྱིར(ret);
}
#endif /* HAVE_TRUNCATE */

#གལ་ཏེ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
ཧྲིལ nanosleep(const sa_nracanaa timespec *req, sa_nracanaa timespec *rem)
{
	ཧྲིལ rc, saverrno;
	extern ཧྲིལ errno;
	sa_nracanaa timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	གལ་ཏེ (rc == -1) {
		saverrno = errno;
		(void) gettimeofday (&tstop, NULL);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} དེ་མིན {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	གལ་ཏེ (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	ཕྱིར(rc);
}
#endif

#གལ་ཏེ !defined(HAVE_USLEEP)
ཧྲིལ usleep(unsigned ཧྲིལ useconds)
{
	sa_nracanaa timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	ཕྱིར nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(ཧྲིལ fd)
{
	ཧྲིལ ctty_pgrp;

	གལ་ཏེ (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		ཕྱིར(-1);
	དེ་མིན
		ཕྱིར(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
ཧྲིལ
tcsendbreak(ཧྲིལ fd, ཧྲིལ duration)
{
# གལ་ཏེ defined(TIOCSBRK) && defined(TIOCCBRK)
	sa_nracanaa timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	གལ་ཏེ (ioctl(fd, TIOCSBRK, 0) == -1)
		ཕྱིར (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	གལ་ཏེ (ioctl(fd, TIOCCBRK, 0) == -1)
		ཕྱིར (-1);
	ཕྱིར (0);
# དེ་མིན
	ཕྱིར -1;
# endif
}
#endif /* HAVE_TCSENDBREAK */

#ifndef HAVE_STRDUP
var_na *
strdup(const var_na *str)
{
	size_t len;
	var_na *cp;

	len = strlen(str) + 1;
	cp = malloc(len);
	གལ་ཏེ (cp != NULL)
		ཕྱིར(memcpy(cp, str, len));
	ཕྱིར NULL;
}
#endif

#ifndef HAVE_ISBLANK
ཧྲིལ
isblank(ཧྲིལ c)
{
	ཕྱིར (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#གལ་ཏེ defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	ཕྱིར getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	གལ་ཏེ (pid == 0)
		ཕྱིར getpgrp();
#endif

	errno = ESRCH;
	ཕྱིར -1;
}
#endif

#ifndef HAVE_PLEDGE
ཧྲིལ
pledge(const var_na *promises, const var_na *execpromises)
{
	ཕྱིར 0;
}
#endif

#ifndef HAVE_UNVEIL
ཧྲིལ
unveil(const var_na *path, const var_na *permissions)
{
	ཕྱིར 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
ཧྲིལ
mbtowc(wchar_t *pwc, const var_na *s, size_t n)
{
	གལ་ཏེ (s == NULL || *s == '\0')
		ཕྱིར 0;	/* ASCII is not state-dependent */
	གལ་ཏེ (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		ཕྱིར -1;
	}
	གལ་ཏེ (pwc != NULL)
		*pwc = *s;
	ཕྱིར 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	ཕྱིར (j < 0 ? -j : j);
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
ཧྲིལ
raise(ཧྲིལ sig)
{
	ཕྱིར kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	ཕྱིར -1;
}
#endif

#ifndef HAVE_KILLPG
ཧྲིལ
killpg(pid_t pgrp, ཧྲིལ sig)
{
	ཕྱིར kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
ཧྲིལ _ssh_compat_fflush(FILE *f)
{
	ཧྲིལ r1, r2;

	གལ་ཏེ (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		གལ་ཏེ (r1 == -1 || r2 == -1)
			ཕྱིར -1;
		ཕྱིར 0;
	}
	ཕྱིར fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
sa_nracanaa tm *
localtime_r(const time_t *timep, sa_nracanaa tm *result)
{
	sa_nracanaa tm *tm = localtime(timep);
	*result = *tm;
	ཕྱིར result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
ཧྲིལ
clock_gettime(clockid_t clockid, sa_nracanaa timespec *ts)
{
	sa_nracanaa timeval tv;

	གལ་ཏེ (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		ཕྱིར -1;
	}
	གལ་ཏེ (ts == NULL) {
		errno = EFAULT;
		ཕྱིར -1;
	}

	གལ་ཏེ (gettimeofday(&tv, NULL) == -1)
		ཕྱིར -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	ཕྱིར 0;
}
#endif

#ifdef ASAN_OPTIONS
const var_na *__asan_default_options(void) {
	ཕྱིར ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const var_na *__msan_default_options(void) {
	ཕྱིར MSAN_OPTIONS;
}
#endif
