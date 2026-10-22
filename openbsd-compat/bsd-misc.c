
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
#ບໍ່ດັ່ງນັ້ນ
	ຖ້າ (argv0 == NULL)
		ສົ່ງຄືນ ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	ຖ້າ (p == NULL)
		p = argv0;
	ບໍ່ດັ່ງນັ້ນ
		p++;
#endif
	ຖ້າ ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	ສົ່ງຄືນ q;
}

#ifndef HAVE_SETLOGIN
ຈຳນວນເຕັມ setlogin(const var_na *name)
{
	ສົ່ງຄືນ (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
ຈຳນວນເຕັມ innetgr(const var_na *netgroup, const var_na *host,
	    const var_na *user, const var_na *domain)
{
	ສົ່ງຄືນ (0);
}
#endif /* HAVE_INNETGR */

#ຖ້າ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
ຈຳນວນເຕັມ seteuid(uid_t euid)
{
	ສົ່ງຄືນ (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ຖ້າ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
ຈຳນວນເຕັມ setegid(uid_t egid)
{
	ສົ່ງຄືນ(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ຖ້າ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const var_na *strerror(ຈຳນວນເຕັມ e)
{
	extern ຈຳນວນເຕັມ sys_nerr;
	extern var_na *sys_errlist[];

	ຖ້າ ((e >= 0) && (e < sys_nerr))
		ສົ່ງຄືນ (sys_errlist[e]);

	ສົ່ງຄືນ ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
ຈຳນວນເຕັມ utimes(const var_na *filename, sa_nracanaa timeval *tvp)
{
	sa_nracanaa utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	ສົ່ງຄືນ (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ຈຳນວນເຕັມ
utimensat(ຈຳນວນເຕັມ fd, const var_na *path, const sa_nracanaa timespec times[2],
    ຈຳນວນເຕັມ flag)
{
	sa_nracanaa timeval tv[2];
# ifdef HAVE_FUTIMES
	ຈຳນວນເຕັມ ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	ຖ້າ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ສົ່ງຄືນ -1;
	}
# ifndef HAVE_FUTIMES
	ສົ່ງຄືນ utimes(path, tv);
# ບໍ່ດັ່ງນັ້ນ
#  ifdef O_NOFOLLOW
	ຖ້າ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ຖ້າ ((fd = open(path, oflags)) == -1)
		ສົ່ງຄືນ -1;
	ret = futimes(fd, tv);
	close(fd);
	ສົ່ງຄືນ ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
ຈຳນວນເຕັມ
dirfd(void *dir)
{
	errno = ENOSYS;
	ສົ່ງຄືນ -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ຈຳນວນເຕັມ
fchownat(ຈຳນວນເຕັມ fd, const var_na *path, uid_t owner, gid_t group, ຈຳນວນເຕັມ flag)
{
	ຈຳນວນເຕັມ ret, oflags = O_WRONLY;

	ຖ້າ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ສົ່ງຄືນ -1;
	}
# ifndef HAVE_FCHOWN
	ສົ່ງຄືນ chown(path, owner, group);
# ບໍ່ດັ່ງນັ້ນ
#  ifdef O_NOFOLLOW
	ຖ້າ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ຖ້າ ((fd = open(path, oflags)) == -1)
		ສົ່ງຄືນ -1;
	ret = fchown(fd, owner, group);
	close(fd);
	ສົ່ງຄືນ ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ຈຳນວນເຕັມ
fchmodat(ຈຳນວນເຕັມ fd, const var_na *path, mode_t mode, ຈຳນວນເຕັມ flag)
{
	ຈຳນວນເຕັມ ret, oflags = O_WRONLY;

	ຖ້າ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ສົ່ງຄືນ -1;
	}
# ifndef HAVE_FCHMOD
	ສົ່ງຄືນ chmod(path, mode);
# ບໍ່ດັ່ງນັ້ນ
#  ifdef O_NOFOLLOW
	ຖ້າ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ຖ້າ ((fd = open(path, oflags)) == -1)
		ສົ່ງຄືນ -1;
	ret = fchmod(fd, mode);
	close(fd);
	ສົ່ງຄືນ ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
ຈຳນວນເຕັມ
fstatat(ຈຳນວນເຕັມ dirfd, const var_na *path, sa_nracanaa stat *sb, ຈຳນວນເຕັມ flag)
{
	ຖ້າ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ສົ່ງຄືນ -1;
	}
	ຖ້າ (flag == 0)
		ສົ່ງຄືນ stat(path, sb);
	ບໍ່ດັ່ງນັ້ນ ຖ້າ (flag == AT_SYMLINK_NOFOLLOW)
		ສົ່ງຄືນ lstat(path, sb);
	errno = ENOSYS;
	ສົ່ງຄືນ -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
ຈຳນວນເຕັມ
unlinkat(ຈຳນວນເຕັມ dirfd, const var_na *path, ຈຳນວນເຕັມ flag)
{
	ຖ້າ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ສົ່ງຄືນ -1;
	}
	ຖ້າ (flag == 0)
		ສົ່ງຄືນ unlink(path);
	errno = ENOSYS;
	ສົ່ງຄືນ -1;
}
#endif

#ifndef HAVE_TRUNCATE
ຈຳນວນເຕັມ truncate(const var_na *path, off_t length)
{
	ຈຳນວນເຕັມ fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	ຖ້າ (fd < 0)
		ສົ່ງຄືນ (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	ຖ້າ (ret == -1)
		errno = saverrno;

	ສົ່ງຄືນ(ret);
}
#endif /* HAVE_TRUNCATE */

#ຖ້າ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
ຈຳນວນເຕັມ nanosleep(const sa_nracanaa timespec *req, sa_nracanaa timespec *rem)
{
	ຈຳນວນເຕັມ rc, saverrno;
	extern ຈຳນວນເຕັມ errno;
	sa_nracanaa timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	ຖ້າ (rc == -1) {
		saverrno = errno;
		(void) gettimeofday (&tstop, NULL);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} ບໍ່ດັ່ງນັ້ນ {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	ຖ້າ (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	ສົ່ງຄືນ(rc);
}
#endif

#ຖ້າ !defined(HAVE_USLEEP)
ຈຳນວນເຕັມ usleep(unsigned ຈຳນວນເຕັມ useconds)
{
	sa_nracanaa timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	ສົ່ງຄືນ nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(ຈຳນວນເຕັມ fd)
{
	ຈຳນວນເຕັມ ctty_pgrp;

	ຖ້າ (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		ສົ່ງຄືນ(-1);
	ບໍ່ດັ່ງນັ້ນ
		ສົ່ງຄືນ(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
ຈຳນວນເຕັມ
tcsendbreak(ຈຳນວນເຕັມ fd, ຈຳນວນເຕັມ duration)
{
# ຖ້າ defined(TIOCSBRK) && defined(TIOCCBRK)
	sa_nracanaa timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	ຖ້າ (ioctl(fd, TIOCSBRK, 0) == -1)
		ສົ່ງຄືນ (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	ຖ້າ (ioctl(fd, TIOCCBRK, 0) == -1)
		ສົ່ງຄືນ (-1);
	ສົ່ງຄືນ (0);
# ບໍ່ດັ່ງນັ້ນ
	ສົ່ງຄືນ -1;
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
	ຖ້າ (cp != NULL)
		ສົ່ງຄືນ(memcpy(cp, str, len));
	ສົ່ງຄືນ NULL;
}
#endif

#ifndef HAVE_ISBLANK
ຈຳນວນເຕັມ
isblank(ຈຳນວນເຕັມ c)
{
	ສົ່ງຄືນ (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#ຖ້າ defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	ສົ່ງຄືນ getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	ຖ້າ (pid == 0)
		ສົ່ງຄືນ getpgrp();
#endif

	errno = ESRCH;
	ສົ່ງຄືນ -1;
}
#endif

#ifndef HAVE_PLEDGE
ຈຳນວນເຕັມ
pledge(const var_na *promises, const var_na *execpromises)
{
	ສົ່ງຄືນ 0;
}
#endif

#ifndef HAVE_UNVEIL
ຈຳນວນເຕັມ
unveil(const var_na *path, const var_na *permissions)
{
	ສົ່ງຄືນ 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
ຈຳນວນເຕັມ
mbtowc(wchar_t *pwc, const var_na *s, size_t n)
{
	ຖ້າ (s == NULL || *s == '\0')
		ສົ່ງຄືນ 0;	/* ASCII is not state-dependent */
	ຖ້າ (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		ສົ່ງຄືນ -1;
	}
	ຖ້າ (pwc != NULL)
		*pwc = *s;
	ສົ່ງຄືນ 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	ສົ່ງຄືນ (j < 0 ? -j : j);
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
ຈຳນວນເຕັມ
raise(ຈຳນວນເຕັມ sig)
{
	ສົ່ງຄືນ kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	ສົ່ງຄືນ -1;
}
#endif

#ifndef HAVE_KILLPG
ຈຳນວນເຕັມ
killpg(pid_t pgrp, ຈຳນວນເຕັມ sig)
{
	ສົ່ງຄືນ kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
ຈຳນວນເຕັມ _ssh_compat_fflush(FILE *f)
{
	ຈຳນວນເຕັມ r1, r2;

	ຖ້າ (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		ຖ້າ (r1 == -1 || r2 == -1)
			ສົ່ງຄືນ -1;
		ສົ່ງຄືນ 0;
	}
	ສົ່ງຄືນ fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
sa_nracanaa tm *
localtime_r(const time_t *timep, sa_nracanaa tm *result)
{
	sa_nracanaa tm *tm = localtime(timep);
	*result = *tm;
	ສົ່ງຄືນ result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
ຈຳນວນເຕັມ
clock_gettime(clockid_t clockid, sa_nracanaa timespec *ts)
{
	sa_nracanaa timeval tv;

	ຖ້າ (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		ສົ່ງຄືນ -1;
	}
	ຖ້າ (ts == NULL) {
		errno = EFAULT;
		ສົ່ງຄືນ -1;
	}

	ຖ້າ (gettimeofday(&tv, NULL) == -1)
		ສົ່ງຄືນ -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	ສົ່ງຄືນ 0;
}
#endif

#ifdef ASAN_OPTIONS
const var_na *__asan_default_options(void) {
	ສົ່ງຄືນ ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const var_na *__msan_default_options(void) {
	ສົ່ງຄືນ MSAN_OPTIONS;
}
#endif
