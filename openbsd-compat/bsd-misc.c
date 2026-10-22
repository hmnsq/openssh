
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
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#ضمن <sys/time.h>

#ضمن <fcntl.h>
#ضمن <string.h>
#ضمن <signal.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <time.h>
#ضمن <unistd.h>

#ifndef HAVE___PROGNAME
حرف *__progname;
#endif

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
حرف *ssh_get_progname(حرف *argv0)
{
	حرف *p, *q;
#ifdef HAVE___PROGNAME
	خارجي حرف *__progname;

	p = __progname;
#وإلا
	إذا (argv0 == عدم)
		إرجاع ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	إذا (p == عدم)
		p = argv0;
	وإلا
		p++;
#endif
	إذا ((q = strdup(p)) == عدم) {
		perror("strdup");
		exit(1);
	}
	إرجاع q;
}

#ifndef HAVE_SETLOGIN
صحيح setlogin(ثابت حرف *name)
{
	إرجاع (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
صحيح innetgr(ثابت حرف *netgroup, ثابت حرف *host,
	    ثابت حرف *user, ثابت حرف *domain)
{
	إرجاع (0);
}
#endif /* HAVE_INNETGR */

#إذا !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
صحيح seteuid(uid_t euid)
{
	إرجاع (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#إذا !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
صحيح setegid(uid_t egid)
{
	إرجاع(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#إذا !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ثابت حرف *strerror(صحيح e)
{
	خارجي صحيح sys_nerr;
	خارجي حرف *sys_errlist[];

	إذا ((e >= 0) && (e < sys_nerr))
		إرجاع (sys_errlist[e]);

	إرجاع ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
صحيح utimes(ثابت حرف *filename, بنية timeval *tvp)
{
	بنية utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	إرجاع (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
صحيح
utimensat(صحيح fd, ثابت حرف *path, ثابت بنية timespec times[2],
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
		إرجاع -1;
	}
# ifndef HAVE_FUTIMES
	إرجاع utimes(path, tv);
# وإلا
#  ifdef O_NOFOLLOW
	إذا (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	إذا ((fd = open(path, oflags)) == -1)
		إرجاع -1;
	ret = futimes(fd, tv);
	close(fd);
	إرجاع ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
صحيح
dirfd(فراغ *dir)
{
	errno = ENOSYS;
	إرجاع -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
صحيح
fchownat(صحيح fd, ثابت حرف *path, uid_t owner, gid_t group, صحيح flag)
{
	صحيح ret, oflags = O_WRONLY;

	إذا (fd != AT_FDCWD) {
		errno = ENOSYS;
		إرجاع -1;
	}
# ifndef HAVE_FCHOWN
	إرجاع chown(path, owner, group);
# وإلا
#  ifdef O_NOFOLLOW
	إذا (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	إذا ((fd = open(path, oflags)) == -1)
		إرجاع -1;
	ret = fchown(fd, owner, group);
	close(fd);
	إرجاع ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
صحيح
fchmodat(صحيح fd, ثابت حرف *path, mode_t mode, صحيح flag)
{
	صحيح ret, oflags = O_WRONLY;

	إذا (fd != AT_FDCWD) {
		errno = ENOSYS;
		إرجاع -1;
	}
# ifndef HAVE_FCHMOD
	إرجاع chmod(path, mode);
# وإلا
#  ifdef O_NOFOLLOW
	إذا (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	إذا ((fd = open(path, oflags)) == -1)
		إرجاع -1;
	ret = fchmod(fd, mode);
	close(fd);
	إرجاع ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
صحيح
fstatat(صحيح dirfd, ثابت حرف *path, بنية stat *sb, صحيح flag)
{
	إذا (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		إرجاع -1;
	}
	إذا (flag == 0)
		إرجاع stat(path, sb);
	وإلا إذا (flag == AT_SYMLINK_NOFOLLOW)
		إرجاع lstat(path, sb);
	errno = ENOSYS;
	إرجاع -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
صحيح
unlinkat(صحيح dirfd, ثابت حرف *path, صحيح flag)
{
	إذا (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		إرجاع -1;
	}
	إذا (flag == 0)
		إرجاع unlink(path);
	errno = ENOSYS;
	إرجاع -1;
}
#endif

#ifndef HAVE_TRUNCATE
صحيح truncate(ثابت حرف *path, off_t length)
{
	صحيح fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	إذا (fd < 0)
		إرجاع (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	إذا (ret == -1)
		errno = saverrno;

	إرجاع(ret);
}
#endif /* HAVE_TRUNCATE */

#إذا !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
صحيح nanosleep(ثابت بنية timespec *req, بنية timespec *rem)
{
	صحيح rc, saverrno;
	خارجي صحيح errno;
	بنية timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
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
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	إرجاع(rc);
}
#endif

#إذا !defined(HAVE_USLEEP)
صحيح usleep(unsigned صحيح useconds)
{
	بنية timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	إرجاع nanosleep(&ts, عدم);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(صحيح fd)
{
	صحيح ctty_pgrp;

	إذا (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		إرجاع(-1);
	وإلا
		إرجاع(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
صحيح
tcsendbreak(صحيح fd, صحيح duration)
{
# إذا defined(TIOCSBRK) && defined(TIOCCBRK)
	بنية timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	إذا (ioctl(fd, TIOCSBRK, 0) == -1)
		إرجاع (-1);
	(فراغ)select(0, 0, 0, 0, &sleepytime);
	إذا (ioctl(fd, TIOCCBRK, 0) == -1)
		إرجاع (-1);
	إرجاع (0);
# وإلا
	إرجاع -1;
# endif
}
#endif /* HAVE_TCSENDBREAK */

#ifndef HAVE_STRDUP
حرف *
strdup(ثابت حرف *str)
{
	size_t len;
	حرف *cp;

	len = strlen(str) + 1;
	cp = malloc(len);
	إذا (cp != عدم)
		إرجاع(memcpy(cp, str, len));
	إرجاع عدم;
}
#endif

#ifndef HAVE_ISBLANK
صحيح
isblank(صحيح c)
{
	إرجاع (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#إذا defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	إرجاع getpgrp(pid);
#وإلاإذا defined(HAVE_GETPGRP)
	إذا (pid == 0)
		إرجاع getpgrp();
#endif

	errno = ESRCH;
	إرجاع -1;
}
#endif

#ifndef HAVE_PLEDGE
صحيح
pledge(ثابت حرف *promises, ثابت حرف *execpromises)
{
	إرجاع 0;
}
#endif

#ifndef HAVE_UNVEIL
صحيح
unveil(ثابت حرف *path, ثابت حرف *permissions)
{
	إرجاع 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
صحيح
mbtowc(wchar_t *pwc, ثابت حرف *s, size_t n)
{
	إذا (s == عدم || *s == '\0')
		إرجاع 0;	/* ASCII is not state-dependent */
	إذا (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		إرجاع -1;
	}
	إذا (pwc != عدم)
		*pwc = *s;
	إرجاع 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	إرجاع (j < 0 ? -j : j);
}
#endif

#ifndef HAVE_BZERO
فراغ
bzero(فراغ *b, size_t n)
{
	(فراغ)memset(b, 0, n);
}
#endif

#ifndef HAVE_RAISE
صحيح
ارفع(صحيح sig)
{
	إرجاع kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	إرجاع -1;
}
#endif

#ifndef HAVE_KILLPG
صحيح
killpg(pid_t pgrp, صحيح sig)
{
	إرجاع kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
صحيح _ssh_compat_fflush(FILE *f)
{
	صحيح r1, r2;

	إذا (f == عدم) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		إذا (r1 == -1 || r2 == -1)
			إرجاع -1;
		إرجاع 0;
	}
	إرجاع fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
بنية tm *
localtime_r(ثابت time_t *timep, بنية tm *result)
{
	بنية tm *tm = localtime(timep);
	*result = *tm;
	إرجاع result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
صحيح
clock_gettime(clockid_t clockid, بنية timespec *ts)
{
	بنية timeval tv;

	إذا (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		إرجاع -1;
	}
	إذا (ts == عدم) {
		errno = EFAULT;
		إرجاع -1;
	}

	إذا (gettimeofday(&tv, عدم) == -1)
		إرجاع -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	إرجاع 0;
}
#endif

#ifdef ASAN_OPTIONS
ثابت حرف *__asan_default_options(فراغ) {
	إرجاع ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
ثابت حرف *__msan_default_options(فراغ) {
	إرجاع MSAN_OPTIONS;
}
#endif
