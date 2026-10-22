
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
	གལ་སྲིད (argv0 == NULL)
		ལོག ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	གལ་སྲིད (p == NULL)
		p = argv0;
	དེ་མིན
		p++;
#endif
	གལ་སྲིད ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	ལོག q;
}

#ifndef HAVE_SETLOGIN
ཧྲིལ setlogin(const var_na *name)
{
	ལོག (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
ཧྲིལ innetgr(const var_na *netgroup, const var_na *host,
	    const var_na *user, const var_na *domain)
{
	ལོག (0);
}
#endif /* HAVE_INNETGR */

#གལ་སྲིད !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
ཧྲིལ seteuid(uid_t euid)
{
	ལོག (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#གལ་སྲིད !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
ཧྲིལ setegid(uid_t egid)
{
	ལོག(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#གལ་སྲིད !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const var_na *strerror(ཧྲིལ e)
{
	extern ཧྲིལ sys_nerr;
	extern var_na *sys_errlist[];

	གལ་སྲིད ((e >= 0) && (e < sys_nerr))
		ལོག (sys_errlist[e]);

	ལོག ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
ཧྲིལ utimes(const var_na *filename, sa_nracanaa timeval *tvp)
{
	sa_nracanaa utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	ལོག (utime(filename, &ub));
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

	གལ་སྲིད (fd != AT_FDCWD) {
		errno = ENOSYS;
		ལོག -1;
	}
# ifndef HAVE_FUTIMES
	ལོག utimes(path, tv);
# དེ་མིན
#  ifdef O_NOFOLLOW
	གལ་སྲིད (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	གལ་སྲིད ((fd = open(path, oflags)) == -1)
		ལོག -1;
	ret = futimes(fd, tv);
	close(fd);
	ལོག ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
ཧྲིལ
dirfd(void *dir)
{
	errno = ENOSYS;
	ལོག -1;
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

	གལ་སྲིད (fd != AT_FDCWD) {
		errno = ENOSYS;
		ལོག -1;
	}
# ifndef HAVE_FCHOWN
	ལོག chown(path, owner, group);
# དེ་མིན
#  ifdef O_NOFOLLOW
	གལ་སྲིད (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	གལ་སྲིད ((fd = open(path, oflags)) == -1)
		ལོག -1;
	ret = fchown(fd, owner, group);
	close(fd);
	ལོག ret;
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

	གལ་སྲིད (fd != AT_FDCWD) {
		errno = ENOSYS;
		ལོག -1;
	}
# ifndef HAVE_FCHMOD
	ལོག chmod(path, mode);
# དེ་མིན
#  ifdef O_NOFOLLOW
	གལ་སྲིད (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	གལ་སྲིད ((fd = open(path, oflags)) == -1)
		ལོག -1;
	ret = fchmod(fd, mode);
	close(fd);
	ལོག ret;
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
	གལ་སྲིད (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ལོག -1;
	}
	གལ་སྲིད (flag == 0)
		ལོག stat(path, sb);
	དེ་མིན གལ་སྲིད (flag == AT_SYMLINK_NOFOLLOW)
		ལོག lstat(path, sb);
	errno = ENOSYS;
	ལོག -1;
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
	གལ་སྲིད (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ལོག -1;
	}
	གལ་སྲིད (flag == 0)
		ལོག unlink(path);
	errno = ENOSYS;
	ལོག -1;
}
#endif

#ifndef HAVE_TRUNCATE
ཧྲིལ truncate(const var_na *path, off_t length)
{
	ཧྲིལ fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	གལ་སྲིད (fd < 0)
		ལོག (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	གལ་སྲིད (ret == -1)
		errno = saverrno;

	ལོག(ret);
}
#endif /* HAVE_TRUNCATE */

#གལ་སྲིད !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
ཧྲིལ nanosleep(const sa_nracanaa timespec *req, sa_nracanaa timespec *rem)
{
	ཧྲིལ rc, saverrno;
	extern ཧྲིལ errno;
	sa_nracanaa timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	གལ་སྲིད (rc == -1) {
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
	གལ་སྲིད (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	ལོག(rc);
}
#endif

#གལ་སྲིད !defined(HAVE_USLEEP)
ཧྲིལ usleep(unsigned ཧྲིལ useconds)
{
	sa_nracanaa timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	ལོག nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(ཧྲིལ fd)
{
	ཧྲིལ ctty_pgrp;

	གལ་སྲིད (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		ལོག(-1);
	དེ་མིན
		ལོག(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
ཧྲིལ
tcsendbreak(ཧྲིལ fd, ཧྲིལ duration)
{
# གལ་སྲིད defined(TIOCSBRK) && defined(TIOCCBRK)
	sa_nracanaa timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	གལ་སྲིད (ioctl(fd, TIOCSBRK, 0) == -1)
		ལོག (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	གལ་སྲིད (ioctl(fd, TIOCCBRK, 0) == -1)
		ལོག (-1);
	ལོག (0);
# དེ་མིན
	ལོག -1;
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
	གལ་སྲིད (cp != NULL)
		ལོག(memcpy(cp, str, len));
	ལོག NULL;
}
#endif

#ifndef HAVE_ISBLANK
ཧྲིལ
isblank(ཧྲིལ c)
{
	ལོག (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#གལ་སྲིད defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	ལོག getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	གལ་སྲིད (pid == 0)
		ལོག getpgrp();
#endif

	errno = ESRCH;
	ལོག -1;
}
#endif

#ifndef HAVE_PLEDGE
ཧྲིལ
pledge(const var_na *promises, const var_na *execpromises)
{
	ལོག 0;
}
#endif

#ifndef HAVE_UNVEIL
ཧྲིལ
unveil(const var_na *path, const var_na *permissions)
{
	ལོག 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
ཧྲིལ
mbtowc(wchar_t *pwc, const var_na *s, size_t n)
{
	གལ་སྲིད (s == NULL || *s == '\0')
		ལོག 0;	/* ASCII is not state-dependent */
	གལ་སྲིད (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		ལོག -1;
	}
	གལ་སྲིད (pwc != NULL)
		*pwc = *s;
	ལོག 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	ལོག (j < 0 ? -j : j);
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
	ལོག kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	ལོག -1;
}
#endif

#ifndef HAVE_KILLPG
ཧྲིལ
killpg(pid_t pgrp, ཧྲིལ sig)
{
	ལོག kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
ཧྲིལ _ssh_compat_fflush(FILE *f)
{
	ཧྲིལ r1, r2;

	གལ་སྲིད (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		གལ་སྲིད (r1 == -1 || r2 == -1)
			ལོག -1;
		ལོག 0;
	}
	ལོག fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
sa_nracanaa tm *
localtime_r(const time_t *timep, sa_nracanaa tm *result)
{
	sa_nracanaa tm *tm = localtime(timep);
	*result = *tm;
	ལོག result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
ཧྲིལ
clock_gettime(clockid_t clockid, sa_nracanaa timespec *ts)
{
	sa_nracanaa timeval tv;

	གལ་སྲིད (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		ལོག -1;
	}
	གལ་སྲིད (ts == NULL) {
		errno = EFAULT;
		ལོག -1;
	}

	གལ་སྲིད (gettimeofday(&tv, NULL) == -1)
		ལོག -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	ལོག 0;
}
#endif

#ifdef ASAN_OPTIONS
const var_na *__asan_default_options(void) {
	ལོག ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const var_na *__msan_default_options(void) {
	ལོག MSAN_OPTIONS;
}
#endif
