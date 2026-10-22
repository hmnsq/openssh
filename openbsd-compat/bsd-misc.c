
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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/ioctl.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#অন্তর্ভাব <sys/time.h>

#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <unistd.h>

#ifndef HAVE___PROGNAME
অক্ষর *__progname;
#endif

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
অক্ষর *ssh_get_progname(অক্ষর *argv0)
{
	অক্ষর *p, *q;
#ifdef HAVE___PROGNAME
	বাহ্যিক অক্ষর *__progname;

	p = __progname;
#অন্যথা
	যদি (argv0 == ফাঁকা)
		ফেরত ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	যদি (p == ফাঁকা)
		p = argv0;
	অন্যথা
		p++;
#endif
	যদি ((q = strdup(p)) == ফাঁকা) {
		perror("strdup");
		exit(1);
	}
	ফেরত q;
}

#ifndef HAVE_SETLOGIN
পূর্ণসংখ্যা setlogin(ধ্রুবক অক্ষর *name)
{
	ফেরত (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
পূর্ণসংখ্যা innetgr(ধ্রুবক অক্ষর *netgroup, ধ্রুবক অক্ষর *host,
	    ধ্রুবক অক্ষর *user, ধ্রুবক অক্ষর *domain)
{
	ফেরত (0);
}
#endif /* HAVE_INNETGR */

#যদি !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
পূর্ণসংখ্যা seteuid(uid_t euid)
{
	ফেরত (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#যদি !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
পূর্ণসংখ্যা setegid(uid_t egid)
{
	ফেরত(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#যদি !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ধ্রুবক অক্ষর *strerror(পূর্ণসংখ্যা e)
{
	বাহ্যিক পূর্ণসংখ্যা sys_nerr;
	বাহ্যিক অক্ষর *sys_errlist[];

	যদি ((e >= 0) && (e < sys_nerr))
		ফেরত (sys_errlist[e]);

	ফেরত ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
পূর্ণসংখ্যা utimes(ধ্রুবক অক্ষর *filename, কাঠামো timeval *tvp)
{
	কাঠামো utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	ফেরত (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
পূর্ণসংখ্যা
utimensat(পূর্ণসংখ্যা fd, ধ্রুবক অক্ষর *path, ধ্রুবক কাঠামো timespec times[2],
    পূর্ণসংখ্যা flag)
{
	কাঠামো timeval tv[2];
# ifdef HAVE_FUTIMES
	পূর্ণসংখ্যা ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	যদি (fd != AT_FDCWD) {
		errno = ENOSYS;
		ফেরত -1;
	}
# ifndef HAVE_FUTIMES
	ফেরত utimes(path, tv);
# অন্যথা
#  ifdef O_NOFOLLOW
	যদি (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	যদি ((fd = open(path, oflags)) == -1)
		ফেরত -1;
	ret = futimes(fd, tv);
	close(fd);
	ফেরত ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
পূর্ণসংখ্যা
dirfd(শূন্য *dir)
{
	errno = ENOSYS;
	ফেরত -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
পূর্ণসংখ্যা
fchownat(পূর্ণসংখ্যা fd, ধ্রুবক অক্ষর *path, uid_t owner, gid_t group, পূর্ণসংখ্যা flag)
{
	পূর্ণসংখ্যা ret, oflags = O_WRONLY;

	যদি (fd != AT_FDCWD) {
		errno = ENOSYS;
		ফেরত -1;
	}
# ifndef HAVE_FCHOWN
	ফেরত chown(path, owner, group);
# অন্যথা
#  ifdef O_NOFOLLOW
	যদি (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	যদি ((fd = open(path, oflags)) == -1)
		ফেরত -1;
	ret = fchown(fd, owner, group);
	close(fd);
	ফেরত ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
পূর্ণসংখ্যা
fchmodat(পূর্ণসংখ্যা fd, ধ্রুবক অক্ষর *path, mode_t mode, পূর্ণসংখ্যা flag)
{
	পূর্ণসংখ্যা ret, oflags = O_WRONLY;

	যদি (fd != AT_FDCWD) {
		errno = ENOSYS;
		ফেরত -1;
	}
# ifndef HAVE_FCHMOD
	ফেরত chmod(path, mode);
# অন্যথা
#  ifdef O_NOFOLLOW
	যদি (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	যদি ((fd = open(path, oflags)) == -1)
		ফেরত -1;
	ret = fchmod(fd, mode);
	close(fd);
	ফেরত ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
পূর্ণসংখ্যা
fstatat(পূর্ণসংখ্যা dirfd, ধ্রুবক অক্ষর *path, কাঠামো stat *sb, পূর্ণসংখ্যা flag)
{
	যদি (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ফেরত -1;
	}
	যদি (flag == 0)
		ফেরত stat(path, sb);
	অন্যথা যদি (flag == AT_SYMLINK_NOFOLLOW)
		ফেরত lstat(path, sb);
	errno = ENOSYS;
	ফেরত -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
পূর্ণসংখ্যা
unlinkat(পূর্ণসংখ্যা dirfd, ধ্রুবক অক্ষর *path, পূর্ণসংখ্যা flag)
{
	যদি (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ফেরত -1;
	}
	যদি (flag == 0)
		ফেরত unlink(path);
	errno = ENOSYS;
	ফেরত -1;
}
#endif

#ifndef HAVE_TRUNCATE
পূর্ণসংখ্যা truncate(ধ্রুবক অক্ষর *path, off_t দৈর্ঘ্য)
{
	পূর্ণসংখ্যা fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	যদি (fd < 0)
		ফেরত (-1);

	ret = ftruncate(fd, দৈর্ঘ্য);
	saverrno = errno;
	close(fd);
	যদি (ret == -1)
		errno = saverrno;

	ফেরত(ret);
}
#endif /* HAVE_TRUNCATE */

#যদি !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
পূর্ণসংখ্যা nanosleep(ধ্রুবক কাঠামো timespec *req, কাঠামো timespec *rem)
{
	পূর্ণসংখ্যা rc, saverrno;
	বাহ্যিক পূর্ণসংখ্যা errno;
	কাঠামো timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(শূন্য) gettimeofday(&tstart, ফাঁকা);
	rc = select(0, ফাঁকা, ফাঁকা, ফাঁকা, &time2wait);
	যদি (rc == -1) {
		saverrno = errno;
		(শূন্য) gettimeofday (&tstop, ফাঁকা);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} অন্যথা {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	যদি (rem != ফাঁকা)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	ফেরত(rc);
}
#endif

#যদি !defined(HAVE_USLEEP)
পূর্ণসংখ্যা usleep(unsigned পূর্ণসংখ্যা useconds)
{
	কাঠামো timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	ফেরত nanosleep(&ts, ফাঁকা);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(পূর্ণসংখ্যা fd)
{
	পূর্ণসংখ্যা ctty_pgrp;

	যদি (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		ফেরত(-1);
	অন্যথা
		ফেরত(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
পূর্ণসংখ্যা
tcsendbreak(পূর্ণসংখ্যা fd, পূর্ণসংখ্যা duration)
{
# যদি defined(TIOCSBRK) && defined(TIOCCBRK)
	কাঠামো timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	যদি (ioctl(fd, TIOCSBRK, 0) == -1)
		ফেরত (-1);
	(শূন্য)select(0, 0, 0, 0, &sleepytime);
	যদি (ioctl(fd, TIOCCBRK, 0) == -1)
		ফেরত (-1);
	ফেরত (0);
# অন্যথা
	ফেরত -1;
# endif
}
#endif /* HAVE_TCSENDBREAK */

#ifndef HAVE_STRDUP
অক্ষর *
strdup(ধ্রুবক অক্ষর *str)
{
	আকার_t len;
	অক্ষর *cp;

	len = strlen(str) + 1;
	cp = malloc(len);
	যদি (cp != ফাঁকা)
		ফেরত(memcpy(cp, str, len));
	ফেরত ফাঁকা;
}
#endif

#ifndef HAVE_ISBLANK
পূর্ণসংখ্যা
isblank(পূর্ণসংখ্যা c)
{
	ফেরত (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#যদি defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	ফেরত getpgrp(pid);
#নতুবা_যদি defined(HAVE_GETPGRP)
	যদি (pid == 0)
		ফেরত getpgrp();
#endif

	errno = ESRCH;
	ফেরত -1;
}
#endif

#ifndef HAVE_PLEDGE
পূর্ণসংখ্যা
pledge(ধ্রুবক অক্ষর *promises, ধ্রুবক অক্ষর *execpromises)
{
	ফেরত 0;
}
#endif

#ifndef HAVE_UNVEIL
পূর্ণসংখ্যা
unveil(ধ্রুবক অক্ষর *path, ধ্রুবক অক্ষর *permissions)
{
	ফেরত 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
পূর্ণসংখ্যা
mbtowc(wchar_t *pwc, ধ্রুবক অক্ষর *s, আকার_t n)
{
	যদি (s == ফাঁকা || *s == '\0')
		ফেরত 0;	/* ASCII is not state-dependent */
	যদি (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		ফেরত -1;
	}
	যদি (pwc != ফাঁকা)
		*pwc = *s;
	ফেরত 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	ফেরত (j < 0 ? -j : j);
}
#endif

#ifndef HAVE_BZERO
শূন্য
bzero(শূন্য *b, আকার_t n)
{
	(শূন্য)memset(b, 0, n);
}
#endif

#ifndef HAVE_RAISE
পূর্ণসংখ্যা
তোলো(পূর্ণসংখ্যা sig)
{
	ফেরত kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	ফেরত -1;
}
#endif

#ifndef HAVE_KILLPG
পূর্ণসংখ্যা
killpg(pid_t pgrp, পূর্ণসংখ্যা sig)
{
	ফেরত kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
পূর্ণসংখ্যা _ssh_compat_fflush(FILE *f)
{
	পূর্ণসংখ্যা r1, r2;

	যদি (f == ফাঁকা) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		যদি (r1 == -1 || r2 == -1)
			ফেরত -1;
		ফেরত 0;
	}
	ফেরত fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
কাঠামো tm *
localtime_r(ধ্রুবক time_t *timep, কাঠামো tm *ফলাফল)
{
	কাঠামো tm *tm = localtime(timep);
	*ফলাফল = *tm;
	ফেরত ফলাফল;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
পূর্ণসংখ্যা
clock_gettime(clockid_t clockid, কাঠামো timespec *ts)
{
	কাঠামো timeval tv;

	যদি (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		ফেরত -1;
	}
	যদি (ts == ফাঁকা) {
		errno = EFAULT;
		ফেরত -1;
	}

	যদি (gettimeofday(&tv, ফাঁকা) == -1)
		ফেরত -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	ফেরত 0;
}
#endif

#ifdef ASAN_OPTIONS
ধ্রুবক অক্ষর *__asan_default_options(শূন্য) {
	ফেরত ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
ধ্রুবক অক্ষর *__msan_default_options(শূন্য) {
	ফেরত MSAN_OPTIONS;
}
#endif
