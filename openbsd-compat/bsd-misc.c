
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
#มิฉะนั้น
	ถ้า (argv0 == NULL)
		คืน ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	ถ้า (p == NULL)
		p = argv0;
	มิฉะนั้น
		p++;
#endif
	ถ้า ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	คืน q;
}

#ifndef HAVE_SETLOGIN
จำนวนเต็ม setlogin(const var_na *name)
{
	คืน (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
จำนวนเต็ม innetgr(const var_na *netgroup, const var_na *host,
	    const var_na *user, const var_na *domain)
{
	คืน (0);
}
#endif /* HAVE_INNETGR */

#ถ้า !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
จำนวนเต็ม seteuid(uid_t euid)
{
	คืน (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ถ้า !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
จำนวนเต็ม setegid(uid_t egid)
{
	คืน(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ถ้า !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const var_na *strerror(จำนวนเต็ม e)
{
	extern จำนวนเต็ม sys_nerr;
	extern var_na *sys_errlist[];

	ถ้า ((e >= 0) && (e < sys_nerr))
		คืน (sys_errlist[e]);

	คืน ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
จำนวนเต็ม utimes(const var_na *filename, sa_nracanaa timeval *tvp)
{
	sa_nracanaa utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	คืน (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
จำนวนเต็ม
utimensat(จำนวนเต็ม fd, const var_na *path, const sa_nracanaa timespec times[2],
    จำนวนเต็ม flag)
{
	sa_nracanaa timeval tv[2];
# ifdef HAVE_FUTIMES
	จำนวนเต็ม ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	ถ้า (fd != AT_FDCWD) {
		errno = ENOSYS;
		คืน -1;
	}
# ifndef HAVE_FUTIMES
	คืน utimes(path, tv);
# มิฉะนั้น
#  ifdef O_NOFOLLOW
	ถ้า (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ถ้า ((fd = open(path, oflags)) == -1)
		คืน -1;
	ret = futimes(fd, tv);
	close(fd);
	คืน ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
จำนวนเต็ม
dirfd(void *dir)
{
	errno = ENOSYS;
	คืน -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
จำนวนเต็ม
fchownat(จำนวนเต็ม fd, const var_na *path, uid_t owner, gid_t group, จำนวนเต็ม flag)
{
	จำนวนเต็ม ret, oflags = O_WRONLY;

	ถ้า (fd != AT_FDCWD) {
		errno = ENOSYS;
		คืน -1;
	}
# ifndef HAVE_FCHOWN
	คืน chown(path, owner, group);
# มิฉะนั้น
#  ifdef O_NOFOLLOW
	ถ้า (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ถ้า ((fd = open(path, oflags)) == -1)
		คืน -1;
	ret = fchown(fd, owner, group);
	close(fd);
	คืน ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
จำนวนเต็ม
fchmodat(จำนวนเต็ม fd, const var_na *path, mode_t mode, จำนวนเต็ม flag)
{
	จำนวนเต็ม ret, oflags = O_WRONLY;

	ถ้า (fd != AT_FDCWD) {
		errno = ENOSYS;
		คืน -1;
	}
# ifndef HAVE_FCHMOD
	คืน chmod(path, mode);
# มิฉะนั้น
#  ifdef O_NOFOLLOW
	ถ้า (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ถ้า ((fd = open(path, oflags)) == -1)
		คืน -1;
	ret = fchmod(fd, mode);
	close(fd);
	คืน ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
จำนวนเต็ม
fstatat(จำนวนเต็ม dirfd, const var_na *path, sa_nracanaa stat *sb, จำนวนเต็ม flag)
{
	ถ้า (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		คืน -1;
	}
	ถ้า (flag == 0)
		คืน stat(path, sb);
	มิฉะนั้น ถ้า (flag == AT_SYMLINK_NOFOLLOW)
		คืน lstat(path, sb);
	errno = ENOSYS;
	คืน -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
จำนวนเต็ม
unlinkat(จำนวนเต็ม dirfd, const var_na *path, จำนวนเต็ม flag)
{
	ถ้า (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		คืน -1;
	}
	ถ้า (flag == 0)
		คืน unlink(path);
	errno = ENOSYS;
	คืน -1;
}
#endif

#ifndef HAVE_TRUNCATE
จำนวนเต็ม truncate(const var_na *path, off_t length)
{
	จำนวนเต็ม fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	ถ้า (fd < 0)
		คืน (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	ถ้า (ret == -1)
		errno = saverrno;

	คืน(ret);
}
#endif /* HAVE_TRUNCATE */

#ถ้า !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
จำนวนเต็ม nanosleep(const sa_nracanaa timespec *req, sa_nracanaa timespec *rem)
{
	จำนวนเต็ม rc, saverrno;
	extern จำนวนเต็ม errno;
	sa_nracanaa timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	ถ้า (rc == -1) {
		saverrno = errno;
		(void) gettimeofday (&tstop, NULL);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} มิฉะนั้น {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	ถ้า (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	คืน(rc);
}
#endif

#ถ้า !defined(HAVE_USLEEP)
จำนวนเต็ม usleep(unsigned จำนวนเต็ม useconds)
{
	sa_nracanaa timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	คืน nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(จำนวนเต็ม fd)
{
	จำนวนเต็ม ctty_pgrp;

	ถ้า (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		คืน(-1);
	มิฉะนั้น
		คืน(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
จำนวนเต็ม
tcsendbreak(จำนวนเต็ม fd, จำนวนเต็ม duration)
{
# ถ้า defined(TIOCSBRK) && defined(TIOCCBRK)
	sa_nracanaa timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	ถ้า (ioctl(fd, TIOCSBRK, 0) == -1)
		คืน (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	ถ้า (ioctl(fd, TIOCCBRK, 0) == -1)
		คืน (-1);
	คืน (0);
# มิฉะนั้น
	คืน -1;
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
	ถ้า (cp != NULL)
		คืน(memcpy(cp, str, len));
	คืน NULL;
}
#endif

#ifndef HAVE_ISBLANK
จำนวนเต็ม
isblank(จำนวนเต็ม c)
{
	คืน (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#ถ้า defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	คืน getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	ถ้า (pid == 0)
		คืน getpgrp();
#endif

	errno = ESRCH;
	คืน -1;
}
#endif

#ifndef HAVE_PLEDGE
จำนวนเต็ม
pledge(const var_na *promises, const var_na *execpromises)
{
	คืน 0;
}
#endif

#ifndef HAVE_UNVEIL
จำนวนเต็ม
unveil(const var_na *path, const var_na *permissions)
{
	คืน 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
จำนวนเต็ม
mbtowc(wchar_t *pwc, const var_na *s, size_t n)
{
	ถ้า (s == NULL || *s == '\0')
		คืน 0;	/* ASCII is not state-dependent */
	ถ้า (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		คืน -1;
	}
	ถ้า (pwc != NULL)
		*pwc = *s;
	คืน 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	คืน (j < 0 ? -j : j);
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
จำนวนเต็ม
raise(จำนวนเต็ม sig)
{
	คืน kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	คืน -1;
}
#endif

#ifndef HAVE_KILLPG
จำนวนเต็ม
killpg(pid_t pgrp, จำนวนเต็ม sig)
{
	คืน kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
จำนวนเต็ม _ssh_compat_fflush(FILE *f)
{
	จำนวนเต็ม r1, r2;

	ถ้า (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		ถ้า (r1 == -1 || r2 == -1)
			คืน -1;
		คืน 0;
	}
	คืน fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
sa_nracanaa tm *
localtime_r(const time_t *timep, sa_nracanaa tm *result)
{
	sa_nracanaa tm *tm = localtime(timep);
	*result = *tm;
	คืน result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
จำนวนเต็ม
clock_gettime(clockid_t clockid, sa_nracanaa timespec *ts)
{
	sa_nracanaa timeval tv;

	ถ้า (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		คืน -1;
	}
	ถ้า (ts == NULL) {
		errno = EFAULT;
		คืน -1;
	}

	ถ้า (gettimeofday(&tv, NULL) == -1)
		คืน -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	คืน 0;
}
#endif

#ifdef ASAN_OPTIONS
const var_na *__asan_default_options(void) {
	คืน ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const var_na *__msan_default_options(void) {
	คืน MSAN_OPTIONS;
}
#endif
