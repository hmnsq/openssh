
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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/ioctl.h>
#నిర్వచితమైతే HAVE_SYS_SELECT_H
# include <sys/select.h>
#అయితే_ముగింపు
#అన్తర్భావ <sys/time.h>

#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <unistd.h>

#నిర్వచితం_కాకపోతే HAVE___PROGNAME
అక్షరం *__progname;
#అయితే_ముగింపు

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
అక్షరం *ssh_get_progname(అక్షరం *argv0)
{
	అక్షరం *p, *q;
#నిర్వచితమైతే HAVE___PROGNAME
	బాహ్య అక్షరం *__progname;

	p = __progname;
#లేకపోతే
	ఒకవేళ (argv0 == ఖాళీ)
		తిరిగి ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	ఒకవేళ (p == ఖాళీ)
		p = argv0;
	లేకపోతే
		p++;
#అయితే_ముగింపు
	ఒకవేళ ((q = strdup(p)) == ఖాళీ) {
		perror("strdup");
		నిష్క్రమించు(1);
	}
	తిరిగి q;
}

#నిర్వచితం_కాకపోతే HAVE_SETLOGIN
పూర్ణాంకం setlogin(స్థిరరాశి అక్షరం *name)
{
	తిరిగి (0);
}
#అయితే_ముగింపు /* !HAVE_SETLOGIN */

#నిర్వచితం_కాకపోతే HAVE_INNETGR
పూర్ణాంకం innetgr(స్థిరరాశి అక్షరం *netgroup, స్థిరరాశి అక్షరం *host,
	    స్థిరరాశి అక్షరం *user, స్థిరరాశి అక్షరం *domain)
{
	తిరిగి (0);
}
#అయితే_ముగింపు /* HAVE_INNETGR */

#ఒకవేళ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
పూర్ణాంకం seteuid(uid_t euid)
{
	తిరిగి (setreuid(-1, euid));
}
#అయితే_ముగింపు /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ఒకవేళ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
పూర్ణాంకం setegid(uid_t egid)
{
	తిరిగి(setresgid(-1, egid, -1));
}
#అయితే_ముగింపు /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ఒకవేళ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
స్థిరరాశి అక్షరం *strerror(పూర్ణాంకం e)
{
	బాహ్య పూర్ణాంకం sys_nerr;
	బాహ్య అక్షరం *sys_errlist[];

	ఒకవేళ ((e >= 0) && (e < sys_nerr))
		తిరిగి (sys_errlist[e]);

	తిరిగి ("unlisted error");
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_UTIMES
పూర్ణాంకం utimes(స్థిరరాశి అక్షరం *filename, నిర్మాణం timeval *tvp)
{
	నిర్మాణం utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	తిరిగి (utime(filename, &ub));
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
పూర్ణాంకం
utimensat(పూర్ణాంకం fd, స్థిరరాశి అక్షరం *మార్గం, స్థిరరాశి నిర్మాణం timespec times[2],
    పూర్ణాంకం flag)
{
	నిర్మాణం timeval tv[2];
# ifdef HAVE_FUTIMES
	పూర్ణాంకం ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	ఒకవేళ (fd != AT_FDCWD) {
		errno = ENOSYS;
		తిరిగి -1;
	}
# ifndef HAVE_FUTIMES
	తిరిగి utimes(మార్గం, tv);
# లేకపోతే
#  ifdef O_NOFOLLOW
	ఒకవేళ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ఒకవేళ ((fd = open(మార్గం, oflags)) == -1)
		తిరిగి -1;
	ret = futimes(fd, tv);
	close(fd);
	తిరిగి ret;
# endif
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_DIRFD
పూర్ణాంకం
dirfd(శూన్య *dir)
{
	errno = ENOSYS;
	తిరిగి -1;
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
పూర్ణాంకం
fchownat(పూర్ణాంకం fd, స్థిరరాశి అక్షరం *మార్గం, uid_t owner, gid_t సమూహం, పూర్ణాంకం flag)
{
	పూర్ణాంకం ret, oflags = O_WRONLY;

	ఒకవేళ (fd != AT_FDCWD) {
		errno = ENOSYS;
		తిరిగి -1;
	}
# ifndef HAVE_FCHOWN
	తిరిగి chown(మార్గం, owner, సమూహం);
# లేకపోతే
#  ifdef O_NOFOLLOW
	ఒకవేళ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ఒకవేళ ((fd = open(మార్గం, oflags)) == -1)
		తిరిగి -1;
	ret = fchown(fd, owner, సమూహం);
	close(fd);
	తిరిగి ret;
# endif
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
పూర్ణాంకం
fchmodat(పూర్ణాంకం fd, స్థిరరాశి అక్షరం *మార్గం, బహుళకం_t బహుళకం, పూర్ణాంకం flag)
{
	పూర్ణాంకం ret, oflags = O_WRONLY;

	ఒకవేళ (fd != AT_FDCWD) {
		errno = ENOSYS;
		తిరిగి -1;
	}
# ifndef HAVE_FCHMOD
	తిరిగి chmod(మార్గం, బహుళకం);
# లేకపోతే
#  ifdef O_NOFOLLOW
	ఒకవేళ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ఒకవేళ ((fd = open(మార్గం, oflags)) == -1)
		తిరిగి -1;
	ret = fchmod(fd, బహుళకం);
	close(fd);
	తిరిగి ret;
# endif
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
పూర్ణాంకం
fstatat(పూర్ణాంకం dirfd, స్థిరరాశి అక్షరం *మార్గం, నిర్మాణం stat *sb, పూర్ణాంకం flag)
{
	ఒకవేళ (dirfd != AT_FDCWD && మార్గం && మార్గం[0] != '/') {
		errno = ENOSYS;
		తిరిగి -1;
	}
	ఒకవేళ (flag == 0)
		తిరిగి stat(మార్గం, sb);
	లేకపోతే ఒకవేళ (flag == AT_SYMLINK_NOFOLLOW)
		తిరిగి lstat(మార్గం, sb);
	errno = ENOSYS;
	తిరిగి -1;
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
పూర్ణాంకం
unlinkat(పూర్ణాంకం dirfd, స్థిరరాశి అక్షరం *మార్గం, పూర్ణాంకం flag)
{
	ఒకవేళ (dirfd != AT_FDCWD && మార్గం && మార్గం[0] != '/') {
		errno = ENOSYS;
		తిరిగి -1;
	}
	ఒకవేళ (flag == 0)
		తిరిగి unlink(మార్గం);
	errno = ENOSYS;
	తిరిగి -1;
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_TRUNCATE
పూర్ణాంకం truncate(స్థిరరాశి అక్షరం *మార్గం, off_t నిడివి)
{
	పూర్ణాంకం fd, ret, saverrno;

	fd = open(మార్గం, O_WRONLY);
	ఒకవేళ (fd < 0)
		తిరిగి (-1);

	ret = ftruncate(fd, నిడివి);
	saverrno = errno;
	close(fd);
	ఒకవేళ (ret == -1)
		errno = saverrno;

	తిరిగి(ret);
}
#అయితే_ముగింపు /* HAVE_TRUNCATE */

#ఒకవేళ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
పూర్ణాంకం nanosleep(స్థిరరాశి నిర్మాణం timespec *req, నిర్మాణం timespec *rem)
{
	పూర్ణాంకం rc, saverrno;
	బాహ్య పూర్ణాంకం errno;
	నిర్మాణం timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_గమ్యం_TIMEVAL(&time2wait, req)
	(శూన్య) gettimeofday(&tstart, ఖాళీ);
	rc = select(0, ఖాళీ, ఖాళీ, ఖాళీ, &time2wait);
	ఒకవేళ (rc == -1) {
		saverrno = errno;
		(శూన్య) gettimeofday (&tstop, ఖాళీ);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} లేకపోతే {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	ఒకవేళ (rem != ఖాళీ)
		TIMEVAL_గమ్యం_TIMESPEC(&tremain, rem)

	తిరిగి(rc);
}
#అయితే_ముగింపు

#ఒకవేళ !defined(HAVE_USLEEP)
పూర్ణాంకం usleep(గుర్తులేని పూర్ణాంకం useconds)
{
	నిర్మాణం timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	తిరిగి nanosleep(&ts, ఖాళీ);
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_TCGETPGRP
pid_t
tcgetpgrp(పూర్ణాంకం fd)
{
	పూర్ణాంకం ctty_pgrp;

	ఒకవేళ (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		తిరిగి(-1);
	లేకపోతే
		తిరిగి(ctty_pgrp);
}
#అయితే_ముగింపు /* HAVE_TCGETPGRP */

#నిర్వచితం_కాకపోతే HAVE_TCSENDBREAK
పూర్ణాంకం
tcsendbreak(పూర్ణాంకం fd, పూర్ణాంకం duration)
{
# ఒకవేళ defined(TIOCSBRK) && defined(TIOCCBRK)
	నిర్మాణం timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	ఒకవేళ (ioctl(fd, TIOCSBRK, 0) == -1)
		తిరిగి (-1);
	(శూన్య)select(0, 0, 0, 0, &sleepytime);
	ఒకవేళ (ioctl(fd, TIOCCBRK, 0) == -1)
		తిరిగి (-1);
	తిరిగి (0);
# లేకపోతే
	తిరిగి -1;
# endif
}
#అయితే_ముగింపు /* HAVE_TCSENDBREAK */

#నిర్వచితం_కాకపోతే HAVE_STRDUP
అక్షరం *
strdup(స్థిరరాశి అక్షరం *str)
{
	కొలత_t len;
	అక్షరం *cp;

	len = అక్షరశ్రేణి_పొడవు(str) + 1;
	cp = జ్ఞాపకం_ఇవ్వు(len);
	ఒకవేళ (cp != ఖాళీ)
		తిరిగి(జ్ఞాపకం_నకలు(cp, str, len));
	తిరిగి ఖాళీ;
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_ISBLANK
పూర్ణాంకం
isblank(పూర్ణాంకం c)
{
	తిరిగి (c == ' ' || c == '\t');
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#ఒకవేళ defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	తిరిగి getpgrp(pid);
#లేదావేళ defined(HAVE_GETPGRP)
	ఒకవేళ (pid == 0)
		తిరిగి getpgrp();
#అయితే_ముగింపు

	errno = ESRCH;
	తిరిగి -1;
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_PLEDGE
పూర్ణాంకం
pledge(స్థిరరాశి అక్షరం *promises, స్థిరరాశి అక్షరం *execpromises)
{
	తిరిగి 0;
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_UNVEIL
పూర్ణాంకం
unveil(స్థిరరాశి అక్షరం *మార్గం, స్థిరరాశి అక్షరం *permissions)
{
	తిరిగి 0;
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
పూర్ణాంకం
mbtowc(wchar_t *pwc, స్థిరరాశి అక్షరం *s, కొలత_t n)
{
	ఒకవేళ (s == ఖాళీ || *s == '\0')
		తిరిగి 0;	/* ASCII is not state-dependent */
	ఒకవేళ (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		తిరిగి -1;
	}
	ఒకవేళ (pwc != ఖాళీ)
		*pwc = *s;
	తిరిగి 1;
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_LLABS
దీర్ఘ దీర్ఘ
llabs(దీర్ఘ దీర్ఘ j)
{
	తిరిగి (j < 0 ? -j : j);
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_BZERO
శూన్య
bzero(శూన్య *b, కొలత_t n)
{
	(శూన్య)memset(b, 0, n);
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_RAISE
పూర్ణాంకం
లేపు(పూర్ణాంకం sig)
{
	తిరిగి kill(getpid(), sig);
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	తిరిగి -1;
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_KILLPG
పూర్ణాంకం
killpg(pid_t pgrp, పూర్ణాంకం sig)
{
	తిరిగి kill(pgrp, sig);
}
#అయితే_ముగింపు

#నిర్వచితమైతే FFLUSH_NULL_BUG
#నిర్వచనం_రద్దు fflush
పూర్ణాంకం _ssh_compat_fflush(FILE *f)
{
	పూర్ణాంకం r1, r2;

	ఒకవేళ (f == ఖాళీ) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		ఒకవేళ (r1 == -1 || r2 == -1)
			తిరిగి -1;
		తిరిగి 0;
	}
	తిరిగి fflush(f);
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_LOCALTIME_R
నిర్మాణం tm *
localtime_r(స్థిరరాశి time_t *timep, నిర్మాణం tm *ఫలితం)
{
	నిర్మాణం tm *tm = localtime(timep);
	*ఫలితం = *tm;
	తిరిగి ఫలితం;
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_CLOCK_GETTIME
పూర్ణాంకం
clock_gettime(clockid_t clockid, నిర్మాణం timespec *ts)
{
	నిర్మాణం timeval tv;

	ఒకవేళ (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		తిరిగి -1;
	}
	ఒకవేళ (ts == ఖాళీ) {
		errno = EFAULT;
		తిరిగి -1;
	}

	ఒకవేళ (gettimeofday(&tv, ఖాళీ) == -1)
		తిరిగి -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (దీర్ఘ)tv.tv_usec * 1000;
	తిరిగి 0;
}
#అయితే_ముగింపు

#నిర్వచితమైతే ASAN_OPTIONS
స్థిరరాశి అక్షరం *__asan_default_options(శూన్య) {
	తిరిగి ASAN_OPTIONS;
}
#అయితే_ముగింపు

#నిర్వచితమైతే MSAN_OPTIONS
స్థిరరాశి అక్షరం *__msan_default_options(శూన్య) {
	తిరిగి MSAN_OPTIONS;
}
#అయితే_ముగింపు
