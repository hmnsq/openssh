
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
#که_تعریف_شوی HAVE_SYS_SELECT_H
# include <sys/select.h>
#د_که_پای
#ضمن <sys/time.h>

#ضمن <fcntl.h>
#ضمن <string.h>
#ضمن <signal.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <time.h>
#ضمن <unistd.h>

#که_نه_تعریف_شوی HAVE___PROGNAME
حرف *__progname;
#د_که_پای

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
حرف *ssh_get_progname(حرف *argv0)
{
	حرف *p, *q;
#که_تعریف_شوی HAVE___PROGNAME
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
#د_که_پای
	إذا ((q = strdup(p)) == عدم) {
		perror("strdup");
		وتل(1);
	}
	أرجع q;
}

#که_نه_تعریف_شوی HAVE_SETLOGIN
صحيح setlogin(ثابت حرف *name)
{
	أرجع (0);
}
#د_که_پای /* !HAVE_SETLOGIN */

#که_نه_تعریف_شوی HAVE_INNETGR
صحيح innetgr(ثابت حرف *netgroup, ثابت حرف *host,
	    ثابت حرف *user, ثابت حرف *domain)
{
	أرجع (0);
}
#د_که_پای /* HAVE_INNETGR */

#إذا !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
صحيح seteuid(uid_t euid)
{
	أرجع (setreuid(-1, euid));
}
#د_که_پای /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#إذا !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
صحيح setegid(uid_t egid)
{
	أرجع(setresgid(-1, egid, -1));
}
#د_که_پای /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#إذا !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ثابت حرف *strerror(صحيح e)
{
	خارجي صحيح sys_nerr;
	خارجي حرف *sys_errlist[];

	إذا ((e >= 0) && (e < sys_nerr))
		أرجع (sys_errlist[e]);

	أرجع ("unlisted error");
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_UTIMES
صحيح utimes(ثابت حرف *filename, بنية timeval *tvp)
{
	بنية utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	أرجع (utime(filename, &ub));
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
صحيح
utimensat(صحيح fd, ثابت حرف *لار, ثابت بنية timespec times[2],
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
	أرجع utimes(لار, tv);
# وإلا
#  ifdef O_NOFOLLOW
	إذا (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	إذا ((fd = open(لار, oflags)) == -1)
		أرجع -1;
	ret = futimes(fd, tv);
	close(fd);
	أرجع ret;
# endif
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_DIRFD
صحيح
dirfd(فراغ *dir)
{
	errno = ENOSYS;
	أرجع -1;
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
صحيح
fchownat(صحيح fd, ثابت حرف *لار, uid_t owner, gid_t ډله, صحيح flag)
{
	صحيح ret, oflags = O_WRONLY;

	إذا (fd != AT_FDCWD) {
		errno = ENOSYS;
		أرجع -1;
	}
# ifndef HAVE_FCHOWN
	أرجع chown(لار, owner, ډله);
# وإلا
#  ifdef O_NOFOLLOW
	إذا (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	إذا ((fd = open(لار, oflags)) == -1)
		أرجع -1;
	ret = fchown(fd, owner, ډله);
	close(fd);
	أرجع ret;
# endif
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
صحيح
fchmodat(صحيح fd, ثابت حرف *لار, ډېرپېښ_t ډېرپېښ, صحيح flag)
{
	صحيح ret, oflags = O_WRONLY;

	إذا (fd != AT_FDCWD) {
		errno = ENOSYS;
		أرجع -1;
	}
# ifndef HAVE_FCHMOD
	أرجع chmod(لار, ډېرپېښ);
# وإلا
#  ifdef O_NOFOLLOW
	إذا (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	إذا ((fd = open(لار, oflags)) == -1)
		أرجع -1;
	ret = fchmod(fd, ډېرپېښ);
	close(fd);
	أرجع ret;
# endif
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
صحيح
fstatat(صحيح dirfd, ثابت حرف *لار, بنية stat *sb, صحيح flag)
{
	إذا (dirfd != AT_FDCWD && لار && لار[0] != '/') {
		errno = ENOSYS;
		أرجع -1;
	}
	إذا (flag == 0)
		أرجع stat(لار, sb);
	وإلا إذا (flag == AT_SYMLINK_NOFOLLOW)
		أرجع lstat(لار, sb);
	errno = ENOSYS;
	أرجع -1;
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
صحيح
unlinkat(صحيح dirfd, ثابت حرف *لار, صحيح flag)
{
	إذا (dirfd != AT_FDCWD && لار && لار[0] != '/') {
		errno = ENOSYS;
		أرجع -1;
	}
	إذا (flag == 0)
		أرجع unlink(لار);
	errno = ENOSYS;
	أرجع -1;
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_TRUNCATE
صحيح truncate(ثابت حرف *لار, off_t اوږدتیا)
{
	صحيح fd, ret, saverrno;

	fd = open(لار, O_WRONLY);
	إذا (fd < 0)
		أرجع (-1);

	ret = ftruncate(fd, اوږدتیا);
	saverrno = errno;
	close(fd);
	إذا (ret == -1)
		errno = saverrno;

	أرجع(ret);
}
#د_که_پای /* HAVE_TRUNCATE */

#إذا !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
صحيح nanosleep(ثابت بنية timespec *req, بنية timespec *rem)
{
	صحيح rc, saverrno;
	خارجي صحيح errno;
	بنية timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_منزل_TIMEVAL(&time2wait, req)
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
		TIMEVAL_منزل_TIMESPEC(&tremain, rem)

	أرجع(rc);
}
#د_که_پای

#إذا !defined(HAVE_USLEEP)
صحيح usleep(بینښه صحيح useconds)
{
	بنية timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	أرجع nanosleep(&ts, عدم);
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_TCGETPGRP
pid_t
tcgetpgrp(صحيح fd)
{
	صحيح ctty_pgrp;

	إذا (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		أرجع(-1);
	وإلا
		أرجع(ctty_pgrp);
}
#د_که_پای /* HAVE_TCGETPGRP */

#که_نه_تعریف_شوی HAVE_TCSENDBREAK
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
#د_که_پای /* HAVE_TCSENDBREAK */

#که_نه_تعریف_شوی HAVE_STRDUP
حرف *
strdup(ثابت حرف *str)
{
	اندازه_t len;
	حرف *cp;

	len = مزي_اوږدوالی(str) + 1;
	cp = حافظه_ورکړه(len);
	إذا (cp != عدم)
		أرجع(حافظه_نقل(cp, str, len));
	أرجع عدم;
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_ISBLANK
صحيح
isblank(صحيح c)
{
	أرجع (c == ' ' || c == '\t');
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#إذا defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	أرجع getpgrp(pid);
#وإلاإذا defined(HAVE_GETPGRP)
	إذا (pid == 0)
		أرجع getpgrp();
#د_که_پای

	errno = ESRCH;
	أرجع -1;
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_PLEDGE
صحيح
pledge(ثابت حرف *promises, ثابت حرف *execpromises)
{
	أرجع 0;
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_UNVEIL
صحيح
unveil(ثابت حرف *لار, ثابت حرف *permissions)
{
	أرجع 0;
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_MBTOWC
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
#د_که_پای

#که_نه_تعریف_شوی HAVE_LLABS
اوږد اوږد
llabs(اوږد اوږد j)
{
	أرجع (j < 0 ? -j : j);
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_BZERO
فراغ
bzero(فراغ *b, اندازه_t n)
{
	(فراغ)memset(b, 0, n);
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_RAISE
صحيح
ارفع(صحيح sig)
{
	أرجع kill(getpid(), sig);
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	أرجع -1;
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_KILLPG
صحيح
killpg(pid_t pgrp, صحيح sig)
{
	أرجع kill(pgrp, sig);
}
#د_که_پای

#که_تعریف_شوی FFLUSH_NULL_BUG
#تعریف_لغوه fflush
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
#د_که_پای

#که_نه_تعریف_شوی HAVE_LOCALTIME_R
بنية tm *
localtime_r(ثابت time_t *timep, بنية tm *پایله)
{
	بنية tm *tm = localtime(timep);
	*پایله = *tm;
	أرجع پایله;
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_CLOCK_GETTIME
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
	ts->tv_nsec = (اوږد)tv.tv_usec * 1000;
	أرجع 0;
}
#د_که_پای

#که_تعریف_شوی ASAN_OPTIONS
ثابت حرف *__asan_default_options(فراغ) {
	أرجع ASAN_OPTIONS;
}
#د_که_پای

#که_تعریف_شوی MSAN_OPTIONS
ثابت حرف *__msan_default_options(فراغ) {
	أرجع MSAN_OPTIONS;
}
#د_که_پای
