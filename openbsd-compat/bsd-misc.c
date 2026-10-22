
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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/ioctl.h>
#اگر_تعریف_شده HAVE_SYS_SELECT_H
# include <sys/select.h>
#پایان_اگر
#ضمن <sys/time.h>

#ضمن <fcntl.h>
#ضمن <string.h>
#ضمن <signal.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <time.h>
#ضمن <unistd.h>

#اگر_تعریف_نشده HAVE___PROGNAME
حرف *__progname;
#پایان_اگر

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
حرف *ssh_get_progname(حرف *argv0)
{
	حرف *p, *q;
#اگر_تعریف_شده HAVE___PROGNAME
	خارجي حرف *__progname;

	p = __progname;
#وإلا
	إذا (argv0 == عدم)
		أرجع ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	إذا (p == عدم)
		p = argv0;
	وإلا
		p++;
#پایان_اگر
	إذا ((q = strdup(p)) == عدم) {
		perror("strdup");
		خروج(1);
	}
	أرجع q;
}

#اگر_تعریف_نشده HAVE_SETLOGIN
صحيح setlogin(ثابت حرف *name)
{
	أرجع (0);
}
#پایان_اگر /* !HAVE_SETLOGIN */

#اگر_تعریف_نشده HAVE_INNETGR
صحيح innetgr(ثابت حرف *netgroup, ثابت حرف *host,
	    ثابت حرف *user, ثابت حرف *domain)
{
	أرجع (0);
}
#پایان_اگر /* HAVE_INNETGR */

#إذا !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
صحيح seteuid(uid_t euid)
{
	أرجع (setreuid(-1, euid));
}
#پایان_اگر /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#إذا !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
صحيح setegid(uid_t egid)
{
	أرجع(setresgid(-1, egid, -1));
}
#پایان_اگر /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#إذا !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ثابت حرف *strerror(صحيح e)
{
	خارجي صحيح sys_nerr;
	خارجي حرف *sys_errlist[];

	إذا ((e >= 0) && (e < sys_nerr))
		أرجع (sys_errlist[e]);

	أرجع ("unlisted error");
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_UTIMES
صحيح utimes(ثابت حرف *filename, بنية timeval *tvp)
{
	بنية utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	أرجع (utime(filename, &ub));
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
صحيح
utimensat(صحيح fd, ثابت حرف *مسیر, ثابت بنية timespec times[2],
    صحيح flag)
{
	بنية timeval tv[2];
# ifdef HAVE_FUTIMES
	صحيح ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	إذا (fd != AT_FDCWD) {
		errno = ENOSYS;
		أرجع -1;
	}
# ifndef HAVE_FUTIMES
	أرجع utimes(مسیر, tv);
# وإلا
#  ifdef O_NOFOLLOW
	إذا (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	إذا ((fd = open(مسیر, oflags)) == -1)
		أرجع -1;
	ret = futimes(fd, tv);
	close(fd);
	أرجع ret;
# endif
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_DIRFD
صحيح
dirfd(فراغ *dir)
{
	errno = ENOSYS;
	أرجع -1;
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
صحيح
fchownat(صحيح fd, ثابت حرف *مسیر, uid_t owner, gid_t گروه, صحيح flag)
{
	صحيح ret, oflags = O_WRONLY;

	إذا (fd != AT_FDCWD) {
		errno = ENOSYS;
		أرجع -1;
	}
# ifndef HAVE_FCHOWN
	أرجع chown(مسیر, owner, گروه);
# وإلا
#  ifdef O_NOFOLLOW
	إذا (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	إذا ((fd = open(مسیر, oflags)) == -1)
		أرجع -1;
	ret = fchown(fd, owner, گروه);
	close(fd);
	أرجع ret;
# endif
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
صحيح
fchmodat(صحيح fd, ثابت حرف *مسیر, نما_t نما, صحيح flag)
{
	صحيح ret, oflags = O_WRONLY;

	إذا (fd != AT_FDCWD) {
		errno = ENOSYS;
		أرجع -1;
	}
# ifndef HAVE_FCHMOD
	أرجع chmod(مسیر, نما);
# وإلا
#  ifdef O_NOFOLLOW
	إذا (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	إذا ((fd = open(مسیر, oflags)) == -1)
		أرجع -1;
	ret = fchmod(fd, نما);
	close(fd);
	أرجع ret;
# endif
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
صحيح
fstatat(صحيح dirfd, ثابت حرف *مسیر, بنية stat *sb, صحيح flag)
{
	إذا (dirfd != AT_FDCWD && مسیر && مسیر[0] != '/') {
		errno = ENOSYS;
		أرجع -1;
	}
	إذا (flag == 0)
		أرجع stat(مسیر, sb);
	وإلا إذا (flag == AT_SYMLINK_NOFOLLOW)
		أرجع lstat(مسیر, sb);
	errno = ENOSYS;
	أرجع -1;
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
صحيح
unlinkat(صحيح dirfd, ثابت حرف *مسیر, صحيح flag)
{
	إذا (dirfd != AT_FDCWD && مسیر && مسیر[0] != '/') {
		errno = ENOSYS;
		أرجع -1;
	}
	إذا (flag == 0)
		أرجع unlink(مسیر);
	errno = ENOSYS;
	أرجع -1;
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_TRUNCATE
صحيح truncate(ثابت حرف *مسیر, off_t درازی)
{
	صحيح fd, ret, saverrno;

	fd = open(مسیر, O_WRONLY);
	إذا (fd < 0)
		أرجع (-1);

	ret = ftruncate(fd, درازی);
	saverrno = errno;
	close(fd);
	إذا (ret == -1)
		errno = saverrno;

	أرجع(ret);
}
#پایان_اگر /* HAVE_TRUNCATE */

#إذا !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
صحيح nanosleep(ثابت بنية timespec *req, بنية timespec *rem)
{
	صحيح rc, saverrno;
	خارجي صحيح errno;
	بنية timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_مقصد_TIMEVAL(&time2wait, req)
	(فراغ) gettimeofday(&tstart, عدم);
	rc = select(0, عدم, عدم, عدم, &time2wait);
	إذا (rc == -1) {
		saverrno = errno;
		(فراغ) gettimeofday (&tstop, عدم);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} وإلا {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	إذا (rem != عدم)
		TIMEVAL_مقصد_TIMESPEC(&tremain, rem)

	أرجع(rc);
}
#پایان_اگر

#إذا !defined(HAVE_USLEEP)
صحيح usleep(بیعلامت صحيح useconds)
{
	بنية timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	أرجع nanosleep(&ts, عدم);
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_TCGETPGRP
pid_t
tcgetpgrp(صحيح fd)
{
	صحيح ctty_pgrp;

	إذا (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		أرجع(-1);
	وإلا
		أرجع(ctty_pgrp);
}
#پایان_اگر /* HAVE_TCGETPGRP */

#اگر_تعریف_نشده HAVE_TCSENDBREAK
صحيح
tcsendbreak(صحيح fd, صحيح duration)
{
# إذا defined(TIOCSBRK) && defined(TIOCCBRK)
	بنية timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	إذا (ioctl(fd, TIOCSBRK, 0) == -1)
		أرجع (-1);
	(فراغ)select(0, 0, 0, 0, &sleepytime);
	إذا (ioctl(fd, TIOCCBRK, 0) == -1)
		أرجع (-1);
	أرجع (0);
# وإلا
	أرجع -1;
# endif
}
#پایان_اگر /* HAVE_TCSENDBREAK */

#اگر_تعریف_نشده HAVE_STRDUP
حرف *
strdup(ثابت حرف *str)
{
	اندازه_t len;
	حرف *cp;

	len = طول_رشته(str) + 1;
	cp = حافظه_بده(len);
	إذا (cp != عدم)
		أرجع(کپی_حافظه(cp, str, len));
	أرجع عدم;
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_ISBLANK
صحيح
isblank(صحيح c)
{
	أرجع (c == ' ' || c == '\t');
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#إذا defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	أرجع getpgrp(pid);
#وإلاإذا defined(HAVE_GETPGRP)
	إذا (pid == 0)
		أرجع getpgrp();
#پایان_اگر

	errno = ESRCH;
	أرجع -1;
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_PLEDGE
صحيح
pledge(ثابت حرف *promises, ثابت حرف *execpromises)
{
	أرجع 0;
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_UNVEIL
صحيح
unveil(ثابت حرف *مسیر, ثابت حرف *permissions)
{
	أرجع 0;
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
صحيح
mbtowc(wchar_t *pwc, ثابت حرف *s, اندازه_t n)
{
	إذا (s == عدم || *s == '\0')
		أرجع 0;	/* ASCII is not state-dependent */
	إذا (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		أرجع -1;
	}
	إذا (pwc != عدم)
		*pwc = *s;
	أرجع 1;
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_LLABS
دراز دراز
llabs(دراز دراز j)
{
	أرجع (j < 0 ? -j : j);
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_BZERO
فراغ
bzero(فراغ *b, اندازه_t n)
{
	(فراغ)memset(b, 0, n);
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_RAISE
صحيح
ارفع(صحيح sig)
{
	أرجع kill(getpid(), sig);
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	أرجع -1;
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_KILLPG
صحيح
killpg(pid_t pgrp, صحيح sig)
{
	أرجع kill(pgrp, sig);
}
#پایان_اگر

#اگر_تعریف_شده FFLUSH_NULL_BUG
#لغو_تعریف fflush
صحيح _ssh_compat_fflush(FILE *f)
{
	صحيح r1, r2;

	إذا (f == عدم) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		إذا (r1 == -1 || r2 == -1)
			أرجع -1;
		أرجع 0;
	}
	أرجع fflush(f);
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_LOCALTIME_R
بنية tm *
localtime_r(ثابت time_t *timep, بنية tm *نتیجه)
{
	بنية tm *tm = localtime(timep);
	*نتیجه = *tm;
	أرجع نتیجه;
}
#پایان_اگر

#اگر_تعریف_نشده HAVE_CLOCK_GETTIME
صحيح
clock_gettime(clockid_t clockid, بنية timespec *ts)
{
	بنية timeval tv;

	إذا (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		أرجع -1;
	}
	إذا (ts == عدم) {
		errno = EFAULT;
		أرجع -1;
	}

	إذا (gettimeofday(&tv, عدم) == -1)
		أرجع -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (دراز)tv.tv_usec * 1000;
	أرجع 0;
}
#پایان_اگر

#اگر_تعریف_شده ASAN_OPTIONS
ثابت حرف *__asan_default_options(فراغ) {
	أرجع ASAN_OPTIONS;
}
#پایان_اگر

#اگر_تعریف_شده MSAN_OPTIONS
ثابت حرف *__msan_default_options(فراغ) {
	أرجع MSAN_OPTIONS;
}
#پایان_اگر
