
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
#បើមិនដូច្នេះ
	ប្រសិនបើ (argv0 == NULL)
		ត្រឡប់ ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	ប្រសិនបើ (p == NULL)
		p = argv0;
	បើមិនដូច្នេះ
		p++;
#endif
	ប្រសិនបើ ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	ត្រឡប់ q;
}

#ifndef HAVE_SETLOGIN
ចំនួនគត់ setlogin(const var_na *name)
{
	ត្រឡប់ (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
ចំនួនគត់ innetgr(const var_na *netgroup, const var_na *host,
	    const var_na *user, const var_na *domain)
{
	ត្រឡប់ (0);
}
#endif /* HAVE_INNETGR */

#ប្រសិនបើ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
ចំនួនគត់ seteuid(uid_t euid)
{
	ត្រឡប់ (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ប្រសិនបើ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
ចំនួនគត់ setegid(uid_t egid)
{
	ត្រឡប់(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ប្រសិនបើ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const var_na *strerror(ចំនួនគត់ e)
{
	extern ចំនួនគត់ sys_nerr;
	extern var_na *sys_errlist[];

	ប្រសិនបើ ((e >= 0) && (e < sys_nerr))
		ត្រឡប់ (sys_errlist[e]);

	ត្រឡប់ ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
ចំនួនគត់ utimes(const var_na *filename, sa_nracanaa timeval *tvp)
{
	sa_nracanaa utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	ត្រឡប់ (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ចំនួនគត់
utimensat(ចំនួនគត់ fd, const var_na *path, const sa_nracanaa timespec times[2],
    ចំនួនគត់ flag)
{
	sa_nracanaa timeval tv[2];
# ifdef HAVE_FUTIMES
	ចំនួនគត់ ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	ប្រសិនបើ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ត្រឡប់ -1;
	}
# ifndef HAVE_FUTIMES
	ត្រឡប់ utimes(path, tv);
# បើមិនដូច្នេះ
#  ifdef O_NOFOLLOW
	ប្រសិនបើ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ប្រសិនបើ ((fd = open(path, oflags)) == -1)
		ត្រឡប់ -1;
	ret = futimes(fd, tv);
	close(fd);
	ត្រឡប់ ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
ចំនួនគត់
dirfd(void *dir)
{
	errno = ENOSYS;
	ត្រឡប់ -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ចំនួនគត់
fchownat(ចំនួនគត់ fd, const var_na *path, uid_t owner, gid_t group, ចំនួនគត់ flag)
{
	ចំនួនគត់ ret, oflags = O_WRONLY;

	ប្រសិនបើ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ត្រឡប់ -1;
	}
# ifndef HAVE_FCHOWN
	ត្រឡប់ chown(path, owner, group);
# បើមិនដូច្នេះ
#  ifdef O_NOFOLLOW
	ប្រសិនបើ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ប្រសិនបើ ((fd = open(path, oflags)) == -1)
		ត្រឡប់ -1;
	ret = fchown(fd, owner, group);
	close(fd);
	ត្រឡប់ ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ចំនួនគត់
fchmodat(ចំនួនគត់ fd, const var_na *path, mode_t mode, ចំនួនគត់ flag)
{
	ចំនួនគត់ ret, oflags = O_WRONLY;

	ប្រសិនបើ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ត្រឡប់ -1;
	}
# ifndef HAVE_FCHMOD
	ត្រឡប់ chmod(path, mode);
# បើមិនដូច្នេះ
#  ifdef O_NOFOLLOW
	ប្រសិនបើ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ប្រសិនបើ ((fd = open(path, oflags)) == -1)
		ត្រឡប់ -1;
	ret = fchmod(fd, mode);
	close(fd);
	ត្រឡប់ ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
ចំនួនគត់
fstatat(ចំនួនគត់ dirfd, const var_na *path, sa_nracanaa stat *sb, ចំនួនគត់ flag)
{
	ប្រសិនបើ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ត្រឡប់ -1;
	}
	ប្រសិនបើ (flag == 0)
		ត្រឡប់ stat(path, sb);
	បើមិនដូច្នេះ ប្រសិនបើ (flag == AT_SYMLINK_NOFOLLOW)
		ត្រឡប់ lstat(path, sb);
	errno = ENOSYS;
	ត្រឡប់ -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
ចំនួនគត់
unlinkat(ចំនួនគត់ dirfd, const var_na *path, ចំនួនគត់ flag)
{
	ប្រសិនបើ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ត្រឡប់ -1;
	}
	ប្រសិនបើ (flag == 0)
		ត្រឡប់ unlink(path);
	errno = ENOSYS;
	ត្រឡប់ -1;
}
#endif

#ifndef HAVE_TRUNCATE
ចំនួនគត់ truncate(const var_na *path, off_t length)
{
	ចំនួនគត់ fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	ប្រសិនបើ (fd < 0)
		ត្រឡប់ (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	ប្រសិនបើ (ret == -1)
		errno = saverrno;

	ត្រឡប់(ret);
}
#endif /* HAVE_TRUNCATE */

#ប្រសិនបើ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
ចំនួនគត់ nanosleep(const sa_nracanaa timespec *req, sa_nracanaa timespec *rem)
{
	ចំនួនគត់ rc, saverrno;
	extern ចំនួនគត់ errno;
	sa_nracanaa timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	ប្រសិនបើ (rc == -1) {
		saverrno = errno;
		(void) gettimeofday (&tstop, NULL);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} បើមិនដូច្នេះ {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	ប្រសិនបើ (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	ត្រឡប់(rc);
}
#endif

#ប្រសិនបើ !defined(HAVE_USLEEP)
ចំនួនគត់ usleep(unsigned ចំនួនគត់ useconds)
{
	sa_nracanaa timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	ត្រឡប់ nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(ចំនួនគត់ fd)
{
	ចំនួនគត់ ctty_pgrp;

	ប្រសិនបើ (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		ត្រឡប់(-1);
	បើមិនដូច្នេះ
		ត្រឡប់(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
ចំនួនគត់
tcsendbreak(ចំនួនគត់ fd, ចំនួនគត់ duration)
{
# ប្រសិនបើ defined(TIOCSBRK) && defined(TIOCCBRK)
	sa_nracanaa timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	ប្រសិនបើ (ioctl(fd, TIOCSBRK, 0) == -1)
		ត្រឡប់ (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	ប្រសិនបើ (ioctl(fd, TIOCCBRK, 0) == -1)
		ត្រឡប់ (-1);
	ត្រឡប់ (0);
# បើមិនដូច្នេះ
	ត្រឡប់ -1;
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
	ប្រសិនបើ (cp != NULL)
		ត្រឡប់(memcpy(cp, str, len));
	ត្រឡប់ NULL;
}
#endif

#ifndef HAVE_ISBLANK
ចំនួនគត់
isblank(ចំនួនគត់ c)
{
	ត្រឡប់ (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#ប្រសិនបើ defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	ត្រឡប់ getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	ប្រសិនបើ (pid == 0)
		ត្រឡប់ getpgrp();
#endif

	errno = ESRCH;
	ត្រឡប់ -1;
}
#endif

#ifndef HAVE_PLEDGE
ចំនួនគត់
pledge(const var_na *promises, const var_na *execpromises)
{
	ត្រឡប់ 0;
}
#endif

#ifndef HAVE_UNVEIL
ចំនួនគត់
unveil(const var_na *path, const var_na *permissions)
{
	ត្រឡប់ 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
ចំនួនគត់
mbtowc(wchar_t *pwc, const var_na *s, size_t n)
{
	ប្រសិនបើ (s == NULL || *s == '\0')
		ត្រឡប់ 0;	/* ASCII is not state-dependent */
	ប្រសិនបើ (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		ត្រឡប់ -1;
	}
	ប្រសិនបើ (pwc != NULL)
		*pwc = *s;
	ត្រឡប់ 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	ត្រឡប់ (j < 0 ? -j : j);
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
ចំនួនគត់
raise(ចំនួនគត់ sig)
{
	ត្រឡប់ kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	ត្រឡប់ -1;
}
#endif

#ifndef HAVE_KILLPG
ចំនួនគត់
killpg(pid_t pgrp, ចំនួនគត់ sig)
{
	ត្រឡប់ kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
ចំនួនគត់ _ssh_compat_fflush(FILE *f)
{
	ចំនួនគត់ r1, r2;

	ប្រសិនបើ (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		ប្រសិនបើ (r1 == -1 || r2 == -1)
			ត្រឡប់ -1;
		ត្រឡប់ 0;
	}
	ត្រឡប់ fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
sa_nracanaa tm *
localtime_r(const time_t *timep, sa_nracanaa tm *result)
{
	sa_nracanaa tm *tm = localtime(timep);
	*result = *tm;
	ត្រឡប់ result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
ចំនួនគត់
clock_gettime(clockid_t clockid, sa_nracanaa timespec *ts)
{
	sa_nracanaa timeval tv;

	ប្រសិនបើ (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		ត្រឡប់ -1;
	}
	ប្រសិនបើ (ts == NULL) {
		errno = EFAULT;
		ត្រឡប់ -1;
	}

	ប្រសិនបើ (gettimeofday(&tv, NULL) == -1)
		ត្រឡប់ -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	ត្រឡប់ 0;
}
#endif

#ifdef ASAN_OPTIONS
const var_na *__asan_default_options(void) {
	ត្រឡប់ ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const var_na *__msan_default_options(void) {
	ត្រឡប់ MSAN_OPTIONS;
}
#endif
