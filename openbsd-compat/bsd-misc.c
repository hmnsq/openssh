
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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/ioctl.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#ಅನ್ತರ್ಭಾವ <sys/time.h>

#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ifndef HAVE___PROGNAME
ವರ್ಣ *__progname;
#endif

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
ವರ್ಣ *ssh_get_progname(ವರ್ಣ *argv0)
{
	ವರ್ಣ *p, *q;
#ifdef HAVE___PROGNAME
	ಬಾಹ್ಯ ವರ್ಣ *__progname;

	p = __progname;
#ಅನ್ಯಥಾ
	ಯದಿ (argv0 == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	ಯದಿ (p == ರಿಕ್ತ)
		p = argv0;
	ಅನ್ಯಥಾ
		p++;
#endif
	ಯದಿ ((q = strdup(p)) == ರಿಕ್ತ) {
		perror("strdup");
		exit(1);
	}
	ಪ್ರತ್ಯಾಗಮ q;
}

#ifndef HAVE_SETLOGIN
ಪೂರ್ಣಾಙ್ಕ setlogin(ಧ್ರುವ ವರ್ಣ *name)
{
	ಪ್ರತ್ಯಾಗಮ (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
ಪೂರ್ಣಾಙ್ಕ innetgr(ಧ್ರುವ ವರ್ಣ *netgroup, ಧ್ರುವ ವರ್ಣ *host,
	    ಧ್ರುವ ವರ್ಣ *user, ಧ್ರುವ ವರ್ಣ *domain)
{
	ಪ್ರತ್ಯಾಗಮ (0);
}
#endif /* HAVE_INNETGR */

#ಯದಿ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
ಪೂರ್ಣಾಙ್ಕ seteuid(uid_t euid)
{
	ಪ್ರತ್ಯಾಗಮ (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ಯದಿ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
ಪೂರ್ಣಾಙ್ಕ setegid(uid_t egid)
{
	ಪ್ರತ್ಯಾಗಮ(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ಯದಿ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ಧ್ರುವ ವರ್ಣ *strerror(ಪೂರ್ಣಾಙ್ಕ e)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ sys_nerr;
	ಬಾಹ್ಯ ವರ್ಣ *sys_errlist[];

	ಯದಿ ((e >= 0) && (e < sys_nerr))
		ಪ್ರತ್ಯಾಗಮ (sys_errlist[e]);

	ಪ್ರತ್ಯಾಗಮ ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
ಪೂರ್ಣಾಙ್ಕ utimes(ಧ್ರುವ ವರ್ಣ *filename, ಸಂರಚನಾ timeval *tvp)
{
	ಸಂರಚನಾ utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	ಪ್ರತ್ಯಾಗಮ (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ಪೂರ್ಣಾಙ್ಕ
utimensat(ಪೂರ್ಣಾಙ್ಕ fd, ಧ್ರುವ ವರ್ಣ *path, ಧ್ರುವ ಸಂರಚನಾ timespec times[2],
    ಪೂರ್ಣಾಙ್ಕ flag)
{
	ಸಂರಚನಾ timeval tv[2];
# ifdef HAVE_FUTIMES
	ಪೂರ್ಣಾಙ್ಕ ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	ಯದಿ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
# ifndef HAVE_FUTIMES
	ಪ್ರತ್ಯಾಗಮ utimes(path, tv);
# ಅನ್ಯಥಾ
#  ifdef O_NOFOLLOW
	ಯದಿ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ಯದಿ ((fd = open(path, oflags)) == -1)
		ಪ್ರತ್ಯಾಗಮ -1;
	ret = futimes(fd, tv);
	close(fd);
	ಪ್ರತ್ಯಾಗಮ ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
ಪೂರ್ಣಾಙ್ಕ
dirfd(ಶೂನ್ಯ *dir)
{
	errno = ENOSYS;
	ಪ್ರತ್ಯಾಗಮ -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ಪೂರ್ಣಾಙ್ಕ
fchownat(ಪೂರ್ಣಾಙ್ಕ fd, ಧ್ರುವ ವರ್ಣ *path, uid_t owner, gid_t group, ಪೂರ್ಣಾಙ್ಕ flag)
{
	ಪೂರ್ಣಾಙ್ಕ ret, oflags = O_WRONLY;

	ಯದಿ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
# ifndef HAVE_FCHOWN
	ಪ್ರತ್ಯಾಗಮ chown(path, owner, group);
# ಅನ್ಯಥಾ
#  ifdef O_NOFOLLOW
	ಯದಿ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ಯದಿ ((fd = open(path, oflags)) == -1)
		ಪ್ರತ್ಯಾಗಮ -1;
	ret = fchown(fd, owner, group);
	close(fd);
	ಪ್ರತ್ಯಾಗಮ ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ಪೂರ್ಣಾಙ್ಕ
fchmodat(ಪೂರ್ಣಾಙ್ಕ fd, ಧ್ರುವ ವರ್ಣ *path, mode_t mode, ಪೂರ್ಣಾಙ್ಕ flag)
{
	ಪೂರ್ಣಾಙ್ಕ ret, oflags = O_WRONLY;

	ಯದಿ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
# ifndef HAVE_FCHMOD
	ಪ್ರತ್ಯಾಗಮ chmod(path, mode);
# ಅನ್ಯಥಾ
#  ifdef O_NOFOLLOW
	ಯದಿ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ಯದಿ ((fd = open(path, oflags)) == -1)
		ಪ್ರತ್ಯಾಗಮ -1;
	ret = fchmod(fd, mode);
	close(fd);
	ಪ್ರತ್ಯಾಗಮ ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
ಪೂರ್ಣಾಙ್ಕ
fstatat(ಪೂರ್ಣಾಙ್ಕ dirfd, ಧ್ರುವ ವರ್ಣ *path, ಸಂರಚನಾ stat *sb, ಪೂರ್ಣಾಙ್ಕ flag)
{
	ಯದಿ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (flag == 0)
		ಪ್ರತ್ಯಾಗಮ stat(path, sb);
	ಅನ್ಯಥಾ ಯದಿ (flag == AT_SYMLINK_NOFOLLOW)
		ಪ್ರತ್ಯಾಗಮ lstat(path, sb);
	errno = ENOSYS;
	ಪ್ರತ್ಯಾಗಮ -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
ಪೂರ್ಣಾಙ್ಕ
unlinkat(ಪೂರ್ಣಾಙ್ಕ dirfd, ಧ್ರುವ ವರ್ಣ *path, ಪೂರ್ಣಾಙ್ಕ flag)
{
	ಯದಿ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (flag == 0)
		ಪ್ರತ್ಯಾಗಮ unlink(path);
	errno = ENOSYS;
	ಪ್ರತ್ಯಾಗಮ -1;
}
#endif

#ifndef HAVE_TRUNCATE
ಪೂರ್ಣಾಙ್ಕ truncate(ಧ್ರುವ ವರ್ಣ *path, off_t length)
{
	ಪೂರ್ಣಾಙ್ಕ fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	ಯದಿ (fd < 0)
		ಪ್ರತ್ಯಾಗಮ (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	ಯದಿ (ret == -1)
		errno = saverrno;

	ಪ್ರತ್ಯಾಗಮ(ret);
}
#endif /* HAVE_TRUNCATE */

#ಯದಿ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
ಪೂರ್ಣಾಙ್ಕ nanosleep(ಧ್ರುವ ಸಂರಚನಾ timespec *req, ಸಂರಚನಾ timespec *rem)
{
	ಪೂರ್ಣಾಙ್ಕ rc, saverrno;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ errno;
	ಸಂರಚನಾ timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(ಶೂನ್ಯ) gettimeofday(&tstart, ರಿಕ್ತ);
	rc = select(0, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, &time2wait);
	ಯದಿ (rc == -1) {
		saverrno = errno;
		(ಶೂನ್ಯ) gettimeofday (&tstop, ರಿಕ್ತ);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} ಅನ್ಯಥಾ {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	ಯದಿ (rem != ರಿಕ್ತ)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	ಪ್ರತ್ಯಾಗಮ(rc);
}
#endif

#ಯದಿ !defined(HAVE_USLEEP)
ಪೂರ್ಣಾಙ್ಕ usleep(unsigned ಪೂರ್ಣಾಙ್ಕ useconds)
{
	ಸಂರಚನಾ timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	ಪ್ರತ್ಯಾಗಮ nanosleep(&ts, ರಿಕ್ತ);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಪೂರ್ಣಾಙ್ಕ ctty_pgrp;

	ಯದಿ (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		ಪ್ರತ್ಯಾಗಮ(-1);
	ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
ಪೂರ್ಣಾಙ್ಕ
tcsendbreak(ಪೂರ್ಣಾಙ್ಕ fd, ಪೂರ್ಣಾಙ್ಕ duration)
{
# ಯದಿ defined(TIOCSBRK) && defined(TIOCCBRK)
	ಸಂರಚನಾ timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	ಯದಿ (ioctl(fd, TIOCSBRK, 0) == -1)
		ಪ್ರತ್ಯಾಗಮ (-1);
	(ಶೂನ್ಯ)select(0, 0, 0, 0, &sleepytime);
	ಯದಿ (ioctl(fd, TIOCCBRK, 0) == -1)
		ಪ್ರತ್ಯಾಗಮ (-1);
	ಪ್ರತ್ಯಾಗಮ (0);
# ಅನ್ಯಥಾ
	ಪ್ರತ್ಯಾಗಮ -1;
# endif
}
#endif /* HAVE_TCSENDBREAK */

#ifndef HAVE_STRDUP
ವರ್ಣ *
strdup(ಧ್ರುವ ವರ್ಣ *str)
{
	size_t len;
	ವರ್ಣ *cp;

	len = strlen(str) + 1;
	cp = malloc(len);
	ಯದಿ (cp != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ(memcpy(cp, str, len));
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}
#endif

#ifndef HAVE_ISBLANK
ಪೂರ್ಣಾಙ್ಕ
isblank(ಪೂರ್ಣಾಙ್ಕ c)
{
	ಪ್ರತ್ಯಾಗಮ (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#ಯದಿ defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	ಪ್ರತ್ಯಾಗಮ getpgrp(pid);
#ನೋಚೇದ್ಯದಿ defined(HAVE_GETPGRP)
	ಯದಿ (pid == 0)
		ಪ್ರತ್ಯಾಗಮ getpgrp();
#endif

	errno = ESRCH;
	ಪ್ರತ್ಯಾಗಮ -1;
}
#endif

#ifndef HAVE_PLEDGE
ಪೂರ್ಣಾಙ್ಕ
pledge(ಧ್ರುವ ವರ್ಣ *promises, ಧ್ರುವ ವರ್ಣ *execpromises)
{
	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif

#ifndef HAVE_UNVEIL
ಪೂರ್ಣಾಙ್ಕ
unveil(ಧ್ರುವ ವರ್ಣ *path, ಧ್ರುವ ವರ್ಣ *permissions)
{
	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
ಪೂರ್ಣಾಙ್ಕ
mbtowc(wchar_t *pwc, ಧ್ರುವ ವರ್ಣ *s, size_t n)
{
	ಯದಿ (s == ರಿಕ್ತ || *s == '\0')
		ಪ್ರತ್ಯಾಗಮ 0;	/* ASCII is not state-dependent */
	ಯದಿ (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (pwc != ರಿಕ್ತ)
		*pwc = *s;
	ಪ್ರತ್ಯಾಗಮ 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	ಪ್ರತ್ಯಾಗಮ (j < 0 ? -j : j);
}
#endif

#ifndef HAVE_BZERO
ಶೂನ್ಯ
bzero(ಶೂನ್ಯ *b, size_t n)
{
	(ಶೂನ್ಯ)memset(b, 0, n);
}
#endif

#ifndef HAVE_RAISE
ಪೂರ್ಣಾಙ್ಕ
ಉತ್ಥಾಪಯ(ಪೂರ್ಣಾಙ್ಕ sig)
{
	ಪ್ರತ್ಯಾಗಮ kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	ಪ್ರತ್ಯಾಗಮ -1;
}
#endif

#ifndef HAVE_KILLPG
ಪೂರ್ಣಾಙ್ಕ
killpg(pid_t pgrp, ಪೂರ್ಣಾಙ್ಕ sig)
{
	ಪ್ರತ್ಯಾಗಮ kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
ಪೂರ್ಣಾಙ್ಕ _ssh_compat_fflush(FILE *f)
{
	ಪೂರ್ಣಾಙ್ಕ r1, r2;

	ಯದಿ (f == ರಿಕ್ತ) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		ಯದಿ (r1 == -1 || r2 == -1)
			ಪ್ರತ್ಯಾಗಮ -1;
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಪ್ರತ್ಯಾಗಮ fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
ಸಂರಚನಾ tm *
localtime_r(ಧ್ರುವ time_t *timep, ಸಂರಚನಾ tm *result)
{
	ಸಂರಚನಾ tm *tm = localtime(timep);
	*result = *tm;
	ಪ್ರತ್ಯಾಗಮ result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
ಪೂರ್ಣಾಙ್ಕ
clock_gettime(clockid_t clockid, ಸಂರಚನಾ timespec *ts)
{
	ಸಂರಚನಾ timeval tv;

	ಯದಿ (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (ts == ರಿಕ್ತ) {
		errno = EFAULT;
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ (gettimeofday(&tv, ರಿಕ್ತ) == -1)
		ಪ್ರತ್ಯಾಗಮ -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif

#ifdef ASAN_OPTIONS
ಧ್ರುವ ವರ್ಣ *__asan_default_options(ಶೂನ್ಯ) {
	ಪ್ರತ್ಯಾಗಮ ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
ಧ್ರುವ ವರ್ಣ *__msan_default_options(ಶೂನ್ಯ) {
	ಪ್ರತ್ಯಾಗಮ MSAN_OPTIONS;
}
#endif
