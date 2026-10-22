
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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/ioctl.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#شامل <sys/time.h>

#شامل <fcntl.h>
#شامل <string.h>
#شامل <signal.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <time.h>
#شامل <unistd.h>

#ifndef HAVE___PROGNAME
نویسه *__progname;
#endif

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
نویسه *ssh_get_progname(نویسه *argv0)
{
	نویسه *p, *q;
#ifdef HAVE___PROGNAME
	بیرونی نویسه *__progname;

	p = __progname;
#وگرنه
	اگر (argv0 == پوچ)
		بازگشت ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	اگر (p == پوچ)
		p = argv0;
	وگرنه
		p++;
#endif
	اگر ((q = strdup(p)) == پوچ) {
		perror("strdup");
		exit(1);
	}
	بازگشت q;
}

#ifndef HAVE_SETLOGIN
صحیح setlogin(ثابت نویسه *name)
{
	بازگشت (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
صحیح innetgr(ثابت نویسه *netgroup, ثابت نویسه *host,
	    ثابت نویسه *user, ثابت نویسه *domain)
{
	بازگشت (0);
}
#endif /* HAVE_INNETGR */

#اگر !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
صحیح seteuid(uid_t euid)
{
	بازگشت (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#اگر !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
صحیح setegid(uid_t egid)
{
	بازگشت(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#اگر !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ثابت نویسه *strerror(صحیح e)
{
	بیرونی صحیح sys_nerr;
	بیرونی نویسه *sys_errlist[];

	اگر ((e >= 0) && (e < sys_nerr))
		بازگشت (sys_errlist[e]);

	بازگشت ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
صحیح utimes(ثابت نویسه *filename, ساختار timeval *tvp)
{
	ساختار utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	بازگشت (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
صحیح
utimensat(صحیح fd, ثابت نویسه *path, ثابت ساختار timespec times[2],
    صحیح flag)
{
	ساختار timeval tv[2];
# ifdef HAVE_FUTIMES
	صحیح ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	اگر (fd != AT_FDCWD) {
		errno = ENOSYS;
		بازگشت -1;
	}
# ifndef HAVE_FUTIMES
	بازگشت utimes(path, tv);
# وگرنه
#  ifdef O_NOFOLLOW
	اگر (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	اگر ((fd = open(path, oflags)) == -1)
		بازگشت -1;
	ret = futimes(fd, tv);
	close(fd);
	بازگشت ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
صحیح
dirfd(تهی *dir)
{
	errno = ENOSYS;
	بازگشت -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
صحیح
fchownat(صحیح fd, ثابت نویسه *path, uid_t owner, gid_t group, صحیح flag)
{
	صحیح ret, oflags = O_WRONLY;

	اگر (fd != AT_FDCWD) {
		errno = ENOSYS;
		بازگشت -1;
	}
# ifndef HAVE_FCHOWN
	بازگشت chown(path, owner, group);
# وگرنه
#  ifdef O_NOFOLLOW
	اگر (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	اگر ((fd = open(path, oflags)) == -1)
		بازگشت -1;
	ret = fchown(fd, owner, group);
	close(fd);
	بازگشت ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
صحیح
fchmodat(صحیح fd, ثابت نویسه *path, mode_t mode, صحیح flag)
{
	صحیح ret, oflags = O_WRONLY;

	اگر (fd != AT_FDCWD) {
		errno = ENOSYS;
		بازگشت -1;
	}
# ifndef HAVE_FCHMOD
	بازگشت chmod(path, mode);
# وگرنه
#  ifdef O_NOFOLLOW
	اگر (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	اگر ((fd = open(path, oflags)) == -1)
		بازگشت -1;
	ret = fchmod(fd, mode);
	close(fd);
	بازگشت ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
صحیح
fstatat(صحیح dirfd, ثابت نویسه *path, ساختار stat *sb, صحیح flag)
{
	اگر (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		بازگشت -1;
	}
	اگر (flag == 0)
		بازگشت stat(path, sb);
	وگرنه اگر (flag == AT_SYMLINK_NOFOLLOW)
		بازگشت lstat(path, sb);
	errno = ENOSYS;
	بازگشت -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
صحیح
unlinkat(صحیح dirfd, ثابت نویسه *path, صحیح flag)
{
	اگر (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		بازگشت -1;
	}
	اگر (flag == 0)
		بازگشت unlink(path);
	errno = ENOSYS;
	بازگشت -1;
}
#endif

#ifndef HAVE_TRUNCATE
صحیح truncate(ثابت نویسه *path, off_t length)
{
	صحیح fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	اگر (fd < 0)
		بازگشت (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	اگر (ret == -1)
		errno = saverrno;

	بازگشت(ret);
}
#endif /* HAVE_TRUNCATE */

#اگر !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
صحیح nanosleep(ثابت ساختار timespec *req, ساختار timespec *rem)
{
	صحیح rc, saverrno;
	بیرونی صحیح errno;
	ساختار timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(تهی) gettimeofday(&tstart, پوچ);
	rc = select(0, پوچ, پوچ, پوچ, &time2wait);
	اگر (rc == -1) {
		saverrno = errno;
		(تهی) gettimeofday (&tstop, پوچ);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} وگرنه {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	اگر (rem != پوچ)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	بازگشت(rc);
}
#endif

#اگر !defined(HAVE_USLEEP)
صحیح usleep(unsigned صحیح useconds)
{
	ساختار timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	بازگشت nanosleep(&ts, پوچ);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(صحیح fd)
{
	صحیح ctty_pgrp;

	اگر (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		بازگشت(-1);
	وگرنه
		بازگشت(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
صحیح
tcsendbreak(صحیح fd, صحیح duration)
{
# اگر defined(TIOCSBRK) && defined(TIOCCBRK)
	ساختار timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	اگر (ioctl(fd, TIOCSBRK, 0) == -1)
		بازگشت (-1);
	(تهی)select(0, 0, 0, 0, &sleepytime);
	اگر (ioctl(fd, TIOCCBRK, 0) == -1)
		بازگشت (-1);
	بازگشت (0);
# وگرنه
	بازگشت -1;
# endif
}
#endif /* HAVE_TCSENDBREAK */

#ifndef HAVE_STRDUP
نویسه *
strdup(ثابت نویسه *str)
{
	size_t len;
	نویسه *cp;

	len = strlen(str) + 1;
	cp = malloc(len);
	اگر (cp != پوچ)
		بازگشت(memcpy(cp, str, len));
	بازگشت پوچ;
}
#endif

#ifndef HAVE_ISBLANK
صحیح
isblank(صحیح c)
{
	بازگشت (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#اگر defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	بازگشت getpgrp(pid);
#وگرنهاگر defined(HAVE_GETPGRP)
	اگر (pid == 0)
		بازگشت getpgrp();
#endif

	errno = ESRCH;
	بازگشت -1;
}
#endif

#ifndef HAVE_PLEDGE
صحیح
pledge(ثابت نویسه *promises, ثابت نویسه *execpromises)
{
	بازگشت 0;
}
#endif

#ifndef HAVE_UNVEIL
صحیح
unveil(ثابت نویسه *path, ثابت نویسه *permissions)
{
	بازگشت 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
صحیح
mbtowc(wchar_t *pwc, ثابت نویسه *s, size_t n)
{
	اگر (s == پوچ || *s == '\0')
		بازگشت 0;	/* ASCII is not state-dependent */
	اگر (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		بازگشت -1;
	}
	اگر (pwc != پوچ)
		*pwc = *s;
	بازگشت 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	بازگشت (j < 0 ? -j : j);
}
#endif

#ifndef HAVE_BZERO
تهی
bzero(تهی *b, size_t n)
{
	(تهی)memset(b, 0, n);
}
#endif

#ifndef HAVE_RAISE
صحیح
بالاببر(صحیح sig)
{
	بازگشت kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	بازگشت -1;
}
#endif

#ifndef HAVE_KILLPG
صحیح
killpg(pid_t pgrp, صحیح sig)
{
	بازگشت kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
صحیح _ssh_compat_fflush(FILE *f)
{
	صحیح r1, r2;

	اگر (f == پوچ) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		اگر (r1 == -1 || r2 == -1)
			بازگشت -1;
		بازگشت 0;
	}
	بازگشت fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
ساختار tm *
localtime_r(ثابت time_t *timep, ساختار tm *result)
{
	ساختار tm *tm = localtime(timep);
	*result = *tm;
	بازگشت result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
صحیح
clock_gettime(clockid_t clockid, ساختار timespec *ts)
{
	ساختار timeval tv;

	اگر (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		بازگشت -1;
	}
	اگر (ts == پوچ) {
		errno = EFAULT;
		بازگشت -1;
	}

	اگر (gettimeofday(&tv, پوچ) == -1)
		بازگشت -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	بازگشت 0;
}
#endif

#ifdef ASAN_OPTIONS
ثابت نویسه *__asan_default_options(تهی) {
	بازگشت ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
ثابت نویسه *__msan_default_options(تهی) {
	بازگشت MSAN_OPTIONS;
}
#endif
