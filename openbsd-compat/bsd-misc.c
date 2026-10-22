
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
বর্ণ *__progname;
#endif

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
বর্ণ *ssh_get_progname(বর্ণ *argv0)
{
	বর্ণ *p, *q;
#ifdef HAVE___PROGNAME
	বাহ্য বর্ণ *__progname;

	p = __progname;
#অন্যথা
	যদি (argv0 == রিক্ত)
		প্রত্যাগম ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	যদি (p == রিক্ত)
		p = argv0;
	অন্যথা
		p++;
#endif
	যদি ((q = strdup(p)) == রিক্ত) {
		perror("strdup");
		exit(1);
	}
	প্রত্যাগম q;
}

#ifndef HAVE_SETLOGIN
পূর্ণাঙ্ক setlogin(ধ্রুব বর্ণ *name)
{
	প্রত্যাগম (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
পূর্ণাঙ্ক innetgr(ধ্রুব বর্ণ *netgroup, ধ্রুব বর্ণ *host,
	    ধ্রুব বর্ণ *user, ধ্রুব বর্ণ *domain)
{
	প্রত্যাগম (0);
}
#endif /* HAVE_INNETGR */

#যদি !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
পূর্ণাঙ্ক seteuid(uid_t euid)
{
	প্রত্যাগম (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#যদি !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
পূর্ণাঙ্ক setegid(uid_t egid)
{
	প্রত্যাগম(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#যদি !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ধ্রুব বর্ণ *strerror(পূর্ণাঙ্ক e)
{
	বাহ্য পূর্ণাঙ্ক sys_nerr;
	বাহ্য বর্ণ *sys_errlist[];

	যদি ((e >= 0) && (e < sys_nerr))
		প্রত্যাগম (sys_errlist[e]);

	প্রত্যাগম ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
পূর্ণাঙ্ক utimes(ধ্রুব বর্ণ *filename, সংরচনা timeval *tvp)
{
	সংরচনা utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	প্রত্যাগম (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
পূর্ণাঙ্ক
utimensat(পূর্ণাঙ্ক fd, ধ্রুব বর্ণ *path, ধ্রুব সংরচনা timespec times[2],
    পূর্ণাঙ্ক flag)
{
	সংরচনা timeval tv[2];
# ifdef HAVE_FUTIMES
	পূর্ণাঙ্ক ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	যদি (fd != AT_FDCWD) {
		errno = ENOSYS;
		প্রত্যাগম -1;
	}
# ifndef HAVE_FUTIMES
	প্রত্যাগম utimes(path, tv);
# অন্যথা
#  ifdef O_NOFOLLOW
	যদি (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	যদি ((fd = open(path, oflags)) == -1)
		প্রত্যাগম -1;
	ret = futimes(fd, tv);
	close(fd);
	প্রত্যাগম ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
পূর্ণাঙ্ক
dirfd(শূন্য *dir)
{
	errno = ENOSYS;
	প্রত্যাগম -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
পূর্ণাঙ্ক
fchownat(পূর্ণাঙ্ক fd, ধ্রুব বর্ণ *path, uid_t owner, gid_t group, পূর্ণাঙ্ক flag)
{
	পূর্ণাঙ্ক ret, oflags = O_WRONLY;

	যদি (fd != AT_FDCWD) {
		errno = ENOSYS;
		প্রত্যাগম -1;
	}
# ifndef HAVE_FCHOWN
	প্রত্যাগম chown(path, owner, group);
# অন্যথা
#  ifdef O_NOFOLLOW
	যদি (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	যদি ((fd = open(path, oflags)) == -1)
		প্রত্যাগম -1;
	ret = fchown(fd, owner, group);
	close(fd);
	প্রত্যাগম ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
পূর্ণাঙ্ক
fchmodat(পূর্ণাঙ্ক fd, ধ্রুব বর্ণ *path, mode_t mode, পূর্ণাঙ্ক flag)
{
	পূর্ণাঙ্ক ret, oflags = O_WRONLY;

	যদি (fd != AT_FDCWD) {
		errno = ENOSYS;
		প্রত্যাগম -1;
	}
# ifndef HAVE_FCHMOD
	প্রত্যাগম chmod(path, mode);
# অন্যথা
#  ifdef O_NOFOLLOW
	যদি (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	যদি ((fd = open(path, oflags)) == -1)
		প্রত্যাগম -1;
	ret = fchmod(fd, mode);
	close(fd);
	প্রত্যাগম ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
পূর্ণাঙ্ক
fstatat(পূর্ণাঙ্ক dirfd, ধ্রুব বর্ণ *path, সংরচনা stat *sb, পূর্ণাঙ্ক flag)
{
	যদি (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		প্রত্যাগম -1;
	}
	যদি (flag == 0)
		প্রত্যাগম stat(path, sb);
	অন্যথা যদি (flag == AT_SYMLINK_NOFOLLOW)
		প্রত্যাগম lstat(path, sb);
	errno = ENOSYS;
	প্রত্যাগম -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
পূর্ণাঙ্ক
unlinkat(পূর্ণাঙ্ক dirfd, ধ্রুব বর্ণ *path, পূর্ণাঙ্ক flag)
{
	যদি (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		প্রত্যাগম -1;
	}
	যদি (flag == 0)
		প্রত্যাগম unlink(path);
	errno = ENOSYS;
	প্রত্যাগম -1;
}
#endif

#ifndef HAVE_TRUNCATE
পূর্ণাঙ্ক truncate(ধ্রুব বর্ণ *path, off_t length)
{
	পূর্ণাঙ্ক fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	যদি (fd < 0)
		প্রত্যাগম (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	যদি (ret == -1)
		errno = saverrno;

	প্রত্যাগম(ret);
}
#endif /* HAVE_TRUNCATE */

#যদি !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
পূর্ণাঙ্ক nanosleep(ধ্রুব সংরচনা timespec *req, সংরচনা timespec *rem)
{
	পূর্ণাঙ্ক rc, saverrno;
	বাহ্য পূর্ণাঙ্ক errno;
	সংরচনা timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(শূন্য) gettimeofday(&tstart, রিক্ত);
	rc = select(0, রিক্ত, রিক্ত, রিক্ত, &time2wait);
	যদি (rc == -1) {
		saverrno = errno;
		(শূন্য) gettimeofday (&tstop, রিক্ত);
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
	যদি (rem != রিক্ত)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	প্রত্যাগম(rc);
}
#endif

#যদি !defined(HAVE_USLEEP)
পূর্ণাঙ্ক usleep(unsigned পূর্ণাঙ্ক useconds)
{
	সংরচনা timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	প্রত্যাগম nanosleep(&ts, রিক্ত);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(পূর্ণাঙ্ক fd)
{
	পূর্ণাঙ্ক ctty_pgrp;

	যদি (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		প্রত্যাগম(-1);
	অন্যথা
		প্রত্যাগম(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
পূর্ণাঙ্ক
tcsendbreak(পূর্ণাঙ্ক fd, পূর্ণাঙ্ক duration)
{
# যদি defined(TIOCSBRK) && defined(TIOCCBRK)
	সংরচনা timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	যদি (ioctl(fd, TIOCSBRK, 0) == -1)
		প্রত্যাগম (-1);
	(শূন্য)select(0, 0, 0, 0, &sleepytime);
	যদি (ioctl(fd, TIOCCBRK, 0) == -1)
		প্রত্যাগম (-1);
	প্রত্যাগম (0);
# অন্যথা
	প্রত্যাগম -1;
# endif
}
#endif /* HAVE_TCSENDBREAK */

#ifndef HAVE_STRDUP
বর্ণ *
strdup(ধ্রুব বর্ণ *str)
{
	size_t len;
	বর্ণ *cp;

	len = strlen(str) + 1;
	cp = malloc(len);
	যদি (cp != রিক্ত)
		প্রত্যাগম(memcpy(cp, str, len));
	প্রত্যাগম রিক্ত;
}
#endif

#ifndef HAVE_ISBLANK
পূর্ণাঙ্ক
isblank(পূর্ণাঙ্ক c)
{
	প্রত্যাগম (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#যদি defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	প্রত্যাগম getpgrp(pid);
#নোচেদ্যদি defined(HAVE_GETPGRP)
	যদি (pid == 0)
		প্রত্যাগম getpgrp();
#endif

	errno = ESRCH;
	প্রত্যাগম -1;
}
#endif

#ifndef HAVE_PLEDGE
পূর্ণাঙ্ক
pledge(ধ্রুব বর্ণ *promises, ধ্রুব বর্ণ *execpromises)
{
	প্রত্যাগম 0;
}
#endif

#ifndef HAVE_UNVEIL
পূর্ণাঙ্ক
unveil(ধ্রুব বর্ণ *path, ধ্রুব বর্ণ *permissions)
{
	প্রত্যাগম 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
পূর্ণাঙ্ক
mbtowc(wchar_t *pwc, ধ্রুব বর্ণ *s, size_t n)
{
	যদি (s == রিক্ত || *s == '\0')
		প্রত্যাগম 0;	/* ASCII is not state-dependent */
	যদি (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		প্রত্যাগম -1;
	}
	যদি (pwc != রিক্ত)
		*pwc = *s;
	প্রত্যাগম 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	প্রত্যাগম (j < 0 ? -j : j);
}
#endif

#ifndef HAVE_BZERO
শূন্য
bzero(শূন্য *b, size_t n)
{
	(শূন্য)memset(b, 0, n);
}
#endif

#ifndef HAVE_RAISE
পূর্ণাঙ্ক
উত্থাপয(পূর্ণাঙ্ক sig)
{
	প্রত্যাগম kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	প্রত্যাগম -1;
}
#endif

#ifndef HAVE_KILLPG
পূর্ণাঙ্ক
killpg(pid_t pgrp, পূর্ণাঙ্ক sig)
{
	প্রত্যাগম kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
পূর্ণাঙ্ক _ssh_compat_fflush(FILE *f)
{
	পূর্ণাঙ্ক r1, r2;

	যদি (f == রিক্ত) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		যদি (r1 == -1 || r2 == -1)
			প্রত্যাগম -1;
		প্রত্যাগম 0;
	}
	প্রত্যাগম fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
সংরচনা tm *
localtime_r(ধ্রুব time_t *timep, সংরচনা tm *result)
{
	সংরচনা tm *tm = localtime(timep);
	*result = *tm;
	প্রত্যাগম result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
পূর্ণাঙ্ক
clock_gettime(clockid_t clockid, সংরচনা timespec *ts)
{
	সংরচনা timeval tv;

	যদি (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		প্রত্যাগম -1;
	}
	যদি (ts == রিক্ত) {
		errno = EFAULT;
		প্রত্যাগম -1;
	}

	যদি (gettimeofday(&tv, রিক্ত) == -1)
		প্রত্যাগম -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	প্রত্যাগম 0;
}
#endif

#ifdef ASAN_OPTIONS
ধ্রুব বর্ণ *__asan_default_options(শূন্য) {
	প্রত্যাগম ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
ধ্রুব বর্ণ *__msan_default_options(শূন্য) {
	প্রত্যাগম MSAN_OPTIONS;
}
#endif
