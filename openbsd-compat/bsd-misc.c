
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
#اگر_تعریف_شدہ HAVE_SYS_SELECT_H
# include <sys/select.h>
#اگر_ختم
#شامل <sys/time.h>

#شامل <fcntl.h>
#شامل <string.h>
#شامل <signal.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <time.h>
#شامل <unistd.h>

#اگر_غیر_تعریف_شدہ HAVE___PROGNAME
حرف *__progname;
#اگر_ختم

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
حرف *ssh_get_progname(حرف *argv0)
{
	حرف *p, *q;
#اگر_تعریف_شدہ HAVE___PROGNAME
	خارجی حرف *__progname;

	p = __progname;
#ورنہ
	اگر (argv0 == تہی)
		واپس ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	اگر (p == تہی)
		p = argv0;
	ورنہ
		p++;
#اگر_ختم
	اگر ((q = strdup(p)) == تہی) {
		perror("strdup");
		باہر_نکلو(1);
	}
	واپس q;
}

#اگر_غیر_تعریف_شدہ HAVE_SETLOGIN
صحیح setlogin(ثابت حرف *name)
{
	واپس (0);
}
#اگر_ختم /* !HAVE_SETLOGIN */

#اگر_غیر_تعریف_شدہ HAVE_INNETGR
صحیح innetgr(ثابت حرف *netgroup, ثابت حرف *host,
	    ثابت حرف *user, ثابت حرف *domain)
{
	واپس (0);
}
#اگر_ختم /* HAVE_INNETGR */

#اگر !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
صحیح seteuid(uid_t euid)
{
	واپس (setreuid(-1, euid));
}
#اگر_ختم /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#اگر !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
صحیح setegid(uid_t egid)
{
	واپس(setresgid(-1, egid, -1));
}
#اگر_ختم /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#اگر !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ثابت حرف *strerror(صحیح e)
{
	خارجی صحیح sys_nerr;
	خارجی حرف *sys_errlist[];

	اگر ((e >= 0) && (e < sys_nerr))
		واپس (sys_errlist[e]);

	واپس ("unlisted error");
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_UTIMES
صحیح utimes(ثابت حرف *filename, ساخت timeval *tvp)
{
	ساخت utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	واپس (utime(filename, &ub));
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
صحیح
utimensat(صحیح fd, ثابت حرف *راستہ, ثابت ساخت timespec times[2],
    صحیح flag)
{
	ساخت timeval tv[2];
# ifdef HAVE_FUTIMES
	صحیح ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	اگر (fd != AT_FDCWD) {
		errno = ENOSYS;
		واپس -1;
	}
# ifndef HAVE_FUTIMES
	واپس utimes(راستہ, tv);
# ورنہ
#  ifdef O_NOFOLLOW
	اگر (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	اگر ((fd = open(راستہ, oflags)) == -1)
		واپس -1;
	ret = futimes(fd, tv);
	close(fd);
	واپس ret;
# endif
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_DIRFD
صحیح
dirfd(خالی *dir)
{
	errno = ENOSYS;
	واپس -1;
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
صحیح
fchownat(صحیح fd, ثابت حرف *راستہ, uid_t owner, gid_t گروہ, صحیح flag)
{
	صحیح ret, oflags = O_WRONLY;

	اگر (fd != AT_FDCWD) {
		errno = ENOSYS;
		واپس -1;
	}
# ifndef HAVE_FCHOWN
	واپس chown(راستہ, owner, گروہ);
# ورنہ
#  ifdef O_NOFOLLOW
	اگر (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	اگر ((fd = open(راستہ, oflags)) == -1)
		واپس -1;
	ret = fchown(fd, owner, گروہ);
	close(fd);
	واپس ret;
# endif
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
صحیح
fchmodat(صحیح fd, ثابت حرف *راستہ, منوال_t منوال, صحیح flag)
{
	صحیح ret, oflags = O_WRONLY;

	اگر (fd != AT_FDCWD) {
		errno = ENOSYS;
		واپس -1;
	}
# ifndef HAVE_FCHMOD
	واپس chmod(راستہ, منوال);
# ورنہ
#  ifdef O_NOFOLLOW
	اگر (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	اگر ((fd = open(راستہ, oflags)) == -1)
		واپس -1;
	ret = fchmod(fd, منوال);
	close(fd);
	واپس ret;
# endif
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
صحیح
fstatat(صحیح dirfd, ثابت حرف *راستہ, ساخت stat *sb, صحیح flag)
{
	اگر (dirfd != AT_FDCWD && راستہ && راستہ[0] != '/') {
		errno = ENOSYS;
		واپس -1;
	}
	اگر (flag == 0)
		واپس stat(راستہ, sb);
	ورنہ اگر (flag == AT_SYMLINK_NOFOLLOW)
		واپس lstat(راستہ, sb);
	errno = ENOSYS;
	واپس -1;
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
صحیح
unlinkat(صحیح dirfd, ثابت حرف *راستہ, صحیح flag)
{
	اگر (dirfd != AT_FDCWD && راستہ && راستہ[0] != '/') {
		errno = ENOSYS;
		واپس -1;
	}
	اگر (flag == 0)
		واپس unlink(راستہ);
	errno = ENOSYS;
	واپس -1;
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_TRUNCATE
صحیح truncate(ثابت حرف *راستہ, off_t لمبائی)
{
	صحیح fd, ret, saverrno;

	fd = open(راستہ, O_WRONLY);
	اگر (fd < 0)
		واپس (-1);

	ret = ftruncate(fd, لمبائی);
	saverrno = errno;
	close(fd);
	اگر (ret == -1)
		errno = saverrno;

	واپس(ret);
}
#اگر_ختم /* HAVE_TRUNCATE */

#اگر !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
صحیح nanosleep(ثابت ساخت timespec *req, ساخت timespec *rem)
{
	صحیح rc, saverrno;
	خارجی صحیح errno;
	ساخت timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_مقصد_TIMEVAL(&time2wait, req)
	(خالی) gettimeofday(&tstart, تہی);
	rc = select(0, تہی, تہی, تہی, &time2wait);
	اگر (rc == -1) {
		saverrno = errno;
		(خالی) gettimeofday (&tstop, تہی);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} ورنہ {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	اگر (rem != تہی)
		TIMEVAL_مقصد_TIMESPEC(&tremain, rem)

	واپس(rc);
}
#اگر_ختم

#اگر !defined(HAVE_USLEEP)
صحیح usleep(غیرعلامتی صحیح useconds)
{
	ساخت timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	واپس nanosleep(&ts, تہی);
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_TCGETPGRP
pid_t
tcgetpgrp(صحیح fd)
{
	صحیح ctty_pgrp;

	اگر (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		واپس(-1);
	ورنہ
		واپس(ctty_pgrp);
}
#اگر_ختم /* HAVE_TCGETPGRP */

#اگر_غیر_تعریف_شدہ HAVE_TCSENDBREAK
صحیح
tcsendbreak(صحیح fd, صحیح duration)
{
# اگر defined(TIOCSBRK) && defined(TIOCCBRK)
	ساخت timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	اگر (ioctl(fd, TIOCSBRK, 0) == -1)
		واپس (-1);
	(خالی)select(0, 0, 0, 0, &sleepytime);
	اگر (ioctl(fd, TIOCCBRK, 0) == -1)
		واپس (-1);
	واپس (0);
# ورنہ
	واپس -1;
# endif
}
#اگر_ختم /* HAVE_TCSENDBREAK */

#اگر_غیر_تعریف_شدہ HAVE_STRDUP
حرف *
strdup(ثابت حرف *str)
{
	سائز_t len;
	حرف *cp;

	len = لڑی_لمبائی(str) + 1;
	cp = حافظہ_دو(len);
	اگر (cp != تہی)
		واپس(حافظہ_نقل(cp, str, len));
	واپس تہی;
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_ISBLANK
صحیح
isblank(صحیح c)
{
	واپس (c == ' ' || c == '\t');
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#اگر defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	واپس getpgrp(pid);
#وگرنہ_اگر defined(HAVE_GETPGRP)
	اگر (pid == 0)
		واپس getpgrp();
#اگر_ختم

	errno = ESRCH;
	واپس -1;
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_PLEDGE
صحیح
pledge(ثابت حرف *promises, ثابت حرف *execpromises)
{
	واپس 0;
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_UNVEIL
صحیح
unveil(ثابت حرف *راستہ, ثابت حرف *permissions)
{
	واپس 0;
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
صحیح
mbtowc(wchar_t *pwc, ثابت حرف *s, سائز_t n)
{
	اگر (s == تہی || *s == '\0')
		واپس 0;	/* ASCII is not state-dependent */
	اگر (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		واپس -1;
	}
	اگر (pwc != تہی)
		*pwc = *s;
	واپس 1;
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_LLABS
طویل طویل
llabs(طویل طویل j)
{
	واپس (j < 0 ? -j : j);
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_BZERO
خالی
bzero(خالی *b, سائز_t n)
{
	(خالی)memset(b, 0, n);
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_RAISE
صحیح
اٹھاؤ(صحیح sig)
{
	واپس kill(getpid(), sig);
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	واپس -1;
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_KILLPG
صحیح
killpg(pid_t pgrp, صحیح sig)
{
	واپس kill(pgrp, sig);
}
#اگر_ختم

#اگر_تعریف_شدہ FFLUSH_NULL_BUG
#تعریف_منسوخ fflush
صحیح _ssh_compat_fflush(FILE *f)
{
	صحیح r1, r2;

	اگر (f == تہی) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		اگر (r1 == -1 || r2 == -1)
			واپس -1;
		واپس 0;
	}
	واپس fflush(f);
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_LOCALTIME_R
ساخت tm *
localtime_r(ثابت time_t *timep, ساخت tm *نتیجہ)
{
	ساخت tm *tm = localtime(timep);
	*نتیجہ = *tm;
	واپس نتیجہ;
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_CLOCK_GETTIME
صحیح
clock_gettime(clockid_t clockid, ساخت timespec *ts)
{
	ساخت timeval tv;

	اگر (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		واپس -1;
	}
	اگر (ts == تہی) {
		errno = EFAULT;
		واپس -1;
	}

	اگر (gettimeofday(&tv, تہی) == -1)
		واپس -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (طویل)tv.tv_usec * 1000;
	واپس 0;
}
#اگر_ختم

#اگر_تعریف_شدہ ASAN_OPTIONS
ثابت حرف *__asan_default_options(خالی) {
	واپس ASAN_OPTIONS;
}
#اگر_ختم

#اگر_تعریف_شدہ MSAN_OPTIONS
ثابت حرف *__msan_default_options(خالی) {
	واپس MSAN_OPTIONS;
}
#اگر_ختم
