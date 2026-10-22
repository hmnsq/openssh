
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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/ioctl.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#அந்தர்பாவ <sys/time.h>

#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <unistd.h>

#ifndef HAVE___PROGNAME
எழுத்து *__progname;
#endif

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
எழுத்து *ssh_get_progname(எழுத்து *argv0)
{
	எழுத்து *p, *q;
#ifdef HAVE___PROGNAME
	வெளி எழுத்து *__progname;

	p = __progname;
#இல்லையெனில்
	எனில் (argv0 == வெற்று)
		திரும்பு ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	எனில் (p == வெற்று)
		p = argv0;
	இல்லையெனில்
		p++;
#endif
	எனில் ((q = strdup(p)) == வெற்று) {
		perror("strdup");
		exit(1);
	}
	திரும்பு q;
}

#ifndef HAVE_SETLOGIN
முழு setlogin(மாறிலி எழுத்து *name)
{
	திரும்பு (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
முழு innetgr(மாறிலி எழுத்து *netgroup, மாறிலி எழுத்து *host,
	    மாறிலி எழுத்து *user, மாறிலி எழுத்து *domain)
{
	திரும்பு (0);
}
#endif /* HAVE_INNETGR */

#எனில் !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
முழு seteuid(uid_t euid)
{
	திரும்பு (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#எனில் !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
முழு setegid(uid_t egid)
{
	திரும்பு(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#எனில் !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
மாறிலி எழுத்து *strerror(முழு e)
{
	வெளி முழு sys_nerr;
	வெளி எழுத்து *sys_errlist[];

	எனில் ((e >= 0) && (e < sys_nerr))
		திரும்பு (sys_errlist[e]);

	திரும்பு ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
முழு utimes(மாறிலி எழுத்து *filename, கட்டமைப்பு timeval *tvp)
{
	கட்டமைப்பு utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	திரும்பு (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
முழு
utimensat(முழு fd, மாறிலி எழுத்து *path, மாறிலி கட்டமைப்பு timespec times[2],
    முழு flag)
{
	கட்டமைப்பு timeval tv[2];
# ifdef HAVE_FUTIMES
	முழு ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	எனில் (fd != AT_FDCWD) {
		errno = ENOSYS;
		திரும்பு -1;
	}
# ifndef HAVE_FUTIMES
	திரும்பு utimes(path, tv);
# இல்லையெனில்
#  ifdef O_NOFOLLOW
	எனில் (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	எனில் ((fd = open(path, oflags)) == -1)
		திரும்பு -1;
	ret = futimes(fd, tv);
	close(fd);
	திரும்பு ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
முழு
dirfd(வெறுமை *dir)
{
	errno = ENOSYS;
	திரும்பு -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
முழு
fchownat(முழு fd, மாறிலி எழுத்து *path, uid_t owner, gid_t group, முழு flag)
{
	முழு ret, oflags = O_WRONLY;

	எனில் (fd != AT_FDCWD) {
		errno = ENOSYS;
		திரும்பு -1;
	}
# ifndef HAVE_FCHOWN
	திரும்பு chown(path, owner, group);
# இல்லையெனில்
#  ifdef O_NOFOLLOW
	எனில் (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	எனில் ((fd = open(path, oflags)) == -1)
		திரும்பு -1;
	ret = fchown(fd, owner, group);
	close(fd);
	திரும்பு ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
முழு
fchmodat(முழு fd, மாறிலி எழுத்து *path, mode_t mode, முழு flag)
{
	முழு ret, oflags = O_WRONLY;

	எனில் (fd != AT_FDCWD) {
		errno = ENOSYS;
		திரும்பு -1;
	}
# ifndef HAVE_FCHMOD
	திரும்பு chmod(path, mode);
# இல்லையெனில்
#  ifdef O_NOFOLLOW
	எனில் (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	எனில் ((fd = open(path, oflags)) == -1)
		திரும்பு -1;
	ret = fchmod(fd, mode);
	close(fd);
	திரும்பு ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
முழு
fstatat(முழு dirfd, மாறிலி எழுத்து *path, கட்டமைப்பு stat *sb, முழு flag)
{
	எனில் (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		திரும்பு -1;
	}
	எனில் (flag == 0)
		திரும்பு stat(path, sb);
	இல்லையெனில் எனில் (flag == AT_SYMLINK_NOFOLLOW)
		திரும்பு lstat(path, sb);
	errno = ENOSYS;
	திரும்பு -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
முழு
unlinkat(முழு dirfd, மாறிலி எழுத்து *path, முழு flag)
{
	எனில் (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		திரும்பு -1;
	}
	எனில் (flag == 0)
		திரும்பு unlink(path);
	errno = ENOSYS;
	திரும்பு -1;
}
#endif

#ifndef HAVE_TRUNCATE
முழு truncate(மாறிலி எழுத்து *path, off_t length)
{
	முழு fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	எனில் (fd < 0)
		திரும்பு (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	எனில் (ret == -1)
		errno = saverrno;

	திரும்பு(ret);
}
#endif /* HAVE_TRUNCATE */

#எனில் !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
முழு nanosleep(மாறிலி கட்டமைப்பு timespec *req, கட்டமைப்பு timespec *rem)
{
	முழு rc, saverrno;
	வெளி முழு errno;
	கட்டமைப்பு timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(வெறுமை) gettimeofday(&tstart, வெற்று);
	rc = select(0, வெற்று, வெற்று, வெற்று, &time2wait);
	எனில் (rc == -1) {
		saverrno = errno;
		(வெறுமை) gettimeofday (&tstop, வெற்று);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} இல்லையெனில் {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	எனில் (rem != வெற்று)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	திரும்பு(rc);
}
#endif

#எனில் !defined(HAVE_USLEEP)
முழு usleep(unsigned முழு useconds)
{
	கட்டமைப்பு timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	திரும்பு nanosleep(&ts, வெற்று);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(முழு fd)
{
	முழு ctty_pgrp;

	எனில் (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		திரும்பு(-1);
	இல்லையெனில்
		திரும்பு(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
முழு
tcsendbreak(முழு fd, முழு duration)
{
# எனில் defined(TIOCSBRK) && defined(TIOCCBRK)
	கட்டமைப்பு timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	எனில் (ioctl(fd, TIOCSBRK, 0) == -1)
		திரும்பு (-1);
	(வெறுமை)select(0, 0, 0, 0, &sleepytime);
	எனில் (ioctl(fd, TIOCCBRK, 0) == -1)
		திரும்பு (-1);
	திரும்பு (0);
# இல்லையெனில்
	திரும்பு -1;
# endif
}
#endif /* HAVE_TCSENDBREAK */

#ifndef HAVE_STRDUP
எழுத்து *
strdup(மாறிலி எழுத்து *str)
{
	size_t len;
	எழுத்து *cp;

	len = strlen(str) + 1;
	cp = malloc(len);
	எனில் (cp != வெற்று)
		திரும்பு(memcpy(cp, str, len));
	திரும்பு வெற்று;
}
#endif

#ifndef HAVE_ISBLANK
முழு
isblank(முழு c)
{
	திரும்பு (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#எனில் defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	திரும்பு getpgrp(pid);
#அல்லதெனில் defined(HAVE_GETPGRP)
	எனில் (pid == 0)
		திரும்பு getpgrp();
#endif

	errno = ESRCH;
	திரும்பு -1;
}
#endif

#ifndef HAVE_PLEDGE
முழு
pledge(மாறிலி எழுத்து *promises, மாறிலி எழுத்து *execpromises)
{
	திரும்பு 0;
}
#endif

#ifndef HAVE_UNVEIL
முழு
unveil(மாறிலி எழுத்து *path, மாறிலி எழுத்து *permissions)
{
	திரும்பு 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
முழு
mbtowc(wchar_t *pwc, மாறிலி எழுத்து *s, size_t n)
{
	எனில் (s == வெற்று || *s == '\0')
		திரும்பு 0;	/* ASCII is not state-dependent */
	எனில் (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		திரும்பு -1;
	}
	எனில் (pwc != வெற்று)
		*pwc = *s;
	திரும்பு 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	திரும்பு (j < 0 ? -j : j);
}
#endif

#ifndef HAVE_BZERO
வெறுமை
bzero(வெறுமை *b, size_t n)
{
	(வெறுமை)memset(b, 0, n);
}
#endif

#ifndef HAVE_RAISE
முழு
எழுப்பு(முழு sig)
{
	திரும்பு kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	திரும்பு -1;
}
#endif

#ifndef HAVE_KILLPG
முழு
killpg(pid_t pgrp, முழு sig)
{
	திரும்பு kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
முழு _ssh_compat_fflush(FILE *f)
{
	முழு r1, r2;

	எனில் (f == வெற்று) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		எனில் (r1 == -1 || r2 == -1)
			திரும்பு -1;
		திரும்பு 0;
	}
	திரும்பு fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
கட்டமைப்பு tm *
localtime_r(மாறிலி time_t *timep, கட்டமைப்பு tm *result)
{
	கட்டமைப்பு tm *tm = localtime(timep);
	*result = *tm;
	திரும்பு result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
முழு
clock_gettime(clockid_t clockid, கட்டமைப்பு timespec *ts)
{
	கட்டமைப்பு timeval tv;

	எனில் (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		திரும்பு -1;
	}
	எனில் (ts == வெற்று) {
		errno = EFAULT;
		திரும்பு -1;
	}

	எனில் (gettimeofday(&tv, வெற்று) == -1)
		திரும்பு -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	திரும்பு 0;
}
#endif

#ifdef ASAN_OPTIONS
மாறிலி எழுத்து *__asan_default_options(வெறுமை) {
	திரும்பு ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
மாறிலி எழுத்து *__msan_default_options(வெறுமை) {
	திரும்பு MSAN_OPTIONS;
}
#endif
