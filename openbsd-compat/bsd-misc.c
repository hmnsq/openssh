
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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/ioctl.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#ଅନ୍ତର୍ଭାଵ <sys/time.h>

#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ifndef HAVE___PROGNAME
ଅକ୍ଷର *__progname;
#endif

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
ଅକ୍ଷର *ssh_get_progname(ଅକ୍ଷର *argv0)
{
	ଅକ୍ଷର *p, *q;
#ifdef HAVE___PROGNAME
	ବାହ୍ୟ ଅକ୍ଷର *__progname;

	p = __progname;
#ଅନ୍ୟଥା
	ଯଦି (argv0 == ଖାଲି)
		ଫେରନ୍ତୁ ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	ଯଦି (p == ଖାଲି)
		p = argv0;
	ଅନ୍ୟଥା
		p++;
#endif
	ଯଦି ((q = strdup(p)) == ଖାଲି) {
		perror("strdup");
		exit(1);
	}
	ଫେରନ୍ତୁ q;
}

#ifndef HAVE_SETLOGIN
ପୂର୍ଣ୍ଣସଂଖ୍ୟା setlogin(ଅଚଳ ଅକ୍ଷର *name)
{
	ଫେରନ୍ତୁ (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
ପୂର୍ଣ୍ଣସଂଖ୍ୟା innetgr(ଅଚଳ ଅକ୍ଷର *netgroup, ଅଚଳ ଅକ୍ଷର *host,
	    ଅଚଳ ଅକ୍ଷର *user, ଅଚଳ ଅକ୍ଷର *domain)
{
	ଫେରନ୍ତୁ (0);
}
#endif /* HAVE_INNETGR */

#ଯଦି !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା seteuid(uid_t euid)
{
	ଫେରନ୍ତୁ (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ଯଦି !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା setegid(uid_t egid)
{
	ଫେରନ୍ତୁ(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ଯଦି !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ଅଚଳ ଅକ୍ଷର *strerror(ପୂର୍ଣ୍ଣସଂଖ୍ୟା e)
{
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା sys_nerr;
	ବାହ୍ୟ ଅକ୍ଷର *sys_errlist[];

	ଯଦି ((e >= 0) && (e < sys_nerr))
		ଫେରନ୍ତୁ (sys_errlist[e]);

	ଫେରନ୍ତୁ ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
ପୂର୍ଣ୍ଣସଂଖ୍ୟା utimes(ଅଚଳ ଅକ୍ଷର *filename, ସଂରଚନା timeval *tvp)
{
	ସଂରଚନା utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	ଫେରନ୍ତୁ (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
utimensat(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଅଚଳ ଅକ୍ଷର *path, ଅଚଳ ସଂରଚନା timespec times[2],
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା flag)
{
	ସଂରଚନା timeval tv[2];
# ifdef HAVE_FUTIMES
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	ଯଦି (fd != AT_FDCWD) {
		errno = ENOSYS;
		ଫେରନ୍ତୁ -1;
	}
# ifndef HAVE_FUTIMES
	ଫେରନ୍ତୁ utimes(path, tv);
# ଅନ୍ୟଥା
#  ifdef O_NOFOLLOW
	ଯଦି (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ଯଦି ((fd = open(path, oflags)) == -1)
		ଫେରନ୍ତୁ -1;
	ret = futimes(fd, tv);
	close(fd);
	ଫେରନ୍ତୁ ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
dirfd(ଶୂନ୍ୟ *dir)
{
	errno = ENOSYS;
	ଫେରନ୍ତୁ -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fchownat(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଅଚଳ ଅକ୍ଷର *path, uid_t owner, gid_t group, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flag)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret, oflags = O_WRONLY;

	ଯଦି (fd != AT_FDCWD) {
		errno = ENOSYS;
		ଫେରନ୍ତୁ -1;
	}
# ifndef HAVE_FCHOWN
	ଫେରନ୍ତୁ chown(path, owner, group);
# ଅନ୍ୟଥା
#  ifdef O_NOFOLLOW
	ଯଦି (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ଯଦି ((fd = open(path, oflags)) == -1)
		ଫେରନ୍ତୁ -1;
	ret = fchown(fd, owner, group);
	close(fd);
	ଫେରନ୍ତୁ ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fchmodat(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଅଚଳ ଅକ୍ଷର *path, mode_t mode, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flag)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret, oflags = O_WRONLY;

	ଯଦି (fd != AT_FDCWD) {
		errno = ENOSYS;
		ଫେରନ୍ତୁ -1;
	}
# ifndef HAVE_FCHMOD
	ଫେରନ୍ତୁ chmod(path, mode);
# ଅନ୍ୟଥା
#  ifdef O_NOFOLLOW
	ଯଦି (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ଯଦି ((fd = open(path, oflags)) == -1)
		ଫେରନ୍ତୁ -1;
	ret = fchmod(fd, mode);
	close(fd);
	ଫେରନ୍ତୁ ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fstatat(ପୂର୍ଣ୍ଣସଂଖ୍ୟା dirfd, ଅଚଳ ଅକ୍ଷର *path, ସଂରଚନା stat *sb, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flag)
{
	ଯଦି (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (flag == 0)
		ଫେରନ୍ତୁ stat(path, sb);
	ଅନ୍ୟଥା ଯଦି (flag == AT_SYMLINK_NOFOLLOW)
		ଫେରନ୍ତୁ lstat(path, sb);
	errno = ENOSYS;
	ଫେରନ୍ତୁ -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
unlinkat(ପୂର୍ଣ୍ଣସଂଖ୍ୟା dirfd, ଅଚଳ ଅକ୍ଷର *path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flag)
{
	ଯଦି (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (flag == 0)
		ଫେରନ୍ତୁ unlink(path);
	errno = ENOSYS;
	ଫେରନ୍ତୁ -1;
}
#endif

#ifndef HAVE_TRUNCATE
ପୂର୍ଣ୍ଣସଂଖ୍ୟା truncate(ଅଚଳ ଅକ୍ଷର *path, off_t length)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	ଯଦି (fd < 0)
		ଫେରନ୍ତୁ (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	ଯଦି (ret == -1)
		errno = saverrno;

	ଫେରନ୍ତୁ(ret);
}
#endif /* HAVE_TRUNCATE */

#ଯଦି !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା nanosleep(ଅଚଳ ସଂରଚନା timespec *req, ସଂରଚନା timespec *rem)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rc, saverrno;
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା errno;
	ସଂରଚନା timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(ଶୂନ୍ୟ) gettimeofday(&tstart, ଖାଲି);
	rc = select(0, ଖାଲି, ଖାଲି, ଖାଲି, &time2wait);
	ଯଦି (rc == -1) {
		saverrno = errno;
		(ଶୂନ୍ୟ) gettimeofday (&tstop, ଖାଲି);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} ଅନ୍ୟଥା {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	ଯଦି (rem != ଖାଲି)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	ଫେରନ୍ତୁ(rc);
}
#endif

#ଯଦି !defined(HAVE_USLEEP)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା usleep(unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା useconds)
{
	ସଂରଚନା timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	ଫେରନ୍ତୁ nanosleep(&ts, ଖାଲି);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ctty_pgrp;

	ଯଦି (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		ଫେରନ୍ତୁ(-1);
	ଅନ୍ୟଥା
		ଫେରନ୍ତୁ(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
tcsendbreak(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା duration)
{
# ଯଦି defined(TIOCSBRK) && defined(TIOCCBRK)
	ସଂରଚନା timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	ଯଦି (ioctl(fd, TIOCSBRK, 0) == -1)
		ଫେରନ୍ତୁ (-1);
	(ଶୂନ୍ୟ)select(0, 0, 0, 0, &sleepytime);
	ଯଦି (ioctl(fd, TIOCCBRK, 0) == -1)
		ଫେରନ୍ତୁ (-1);
	ଫେରନ୍ତୁ (0);
# ଅନ୍ୟଥା
	ଫେରନ୍ତୁ -1;
# endif
}
#endif /* HAVE_TCSENDBREAK */

#ifndef HAVE_STRDUP
ଅକ୍ଷର *
strdup(ଅଚଳ ଅକ୍ଷର *str)
{
	size_t len;
	ଅକ୍ଷର *cp;

	len = strlen(str) + 1;
	cp = malloc(len);
	ଯଦି (cp != ଖାଲି)
		ଫେରନ୍ତୁ(memcpy(cp, str, len));
	ଫେରନ୍ତୁ ଖାଲି;
}
#endif

#ifndef HAVE_ISBLANK
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
isblank(ପୂର୍ଣ୍ଣସଂଖ୍ୟା c)
{
	ଫେରନ୍ତୁ (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#ଯଦି defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	ଫେରନ୍ତୁ getpgrp(pid);
#ନଚେତଯଦି defined(HAVE_GETPGRP)
	ଯଦି (pid == 0)
		ଫେରନ୍ତୁ getpgrp();
#endif

	errno = ESRCH;
	ଫେରନ୍ତୁ -1;
}
#endif

#ifndef HAVE_PLEDGE
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pledge(ଅଚଳ ଅକ୍ଷର *promises, ଅଚଳ ଅକ୍ଷର *execpromises)
{
	ଫେରନ୍ତୁ 0;
}
#endif

#ifndef HAVE_UNVEIL
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
unveil(ଅଚଳ ଅକ୍ଷର *path, ଅଚଳ ଅକ୍ଷର *permissions)
{
	ଫେରନ୍ତୁ 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mbtowc(wchar_t *pwc, ଅଚଳ ଅକ୍ଷର *s, size_t n)
{
	ଯଦି (s == ଖାଲି || *s == '\0')
		ଫେରନ୍ତୁ 0;	/* ASCII is not state-dependent */
	ଯଦି (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (pwc != ଖାଲି)
		*pwc = *s;
	ଫେରନ୍ତୁ 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	ଫେରନ୍ତୁ (j < 0 ? -j : j);
}
#endif

#ifndef HAVE_BZERO
ଶୂନ୍ୟ
bzero(ଶୂନ୍ୟ *b, size_t n)
{
	(ଶୂନ୍ୟ)memset(b, 0, n);
}
#endif

#ifndef HAVE_RAISE
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ଉଠାଅ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	ଫେରନ୍ତୁ kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	ଫେରନ୍ତୁ -1;
}
#endif

#ifndef HAVE_KILLPG
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
killpg(pid_t pgrp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	ଫେରନ୍ତୁ kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
ପୂର୍ଣ୍ଣସଂଖ୍ୟା _ssh_compat_fflush(FILE *f)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r1, r2;

	ଯଦି (f == ଖାଲି) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		ଯଦି (r1 == -1 || r2 == -1)
			ଫେରନ୍ତୁ -1;
		ଫେରନ୍ତୁ 0;
	}
	ଫେରନ୍ତୁ fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
ସଂରଚନା tm *
localtime_r(ଅଚଳ time_t *timep, ସଂରଚନା tm *result)
{
	ସଂରଚନା tm *tm = localtime(timep);
	*result = *tm;
	ଫେରନ୍ତୁ result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
clock_gettime(clockid_t clockid, ସଂରଚନା timespec *ts)
{
	ସଂରଚନା timeval tv;

	ଯଦି (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (ts == ଖାଲି) {
		errno = EFAULT;
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି (gettimeofday(&tv, ଖାଲି) == -1)
		ଫେରନ୍ତୁ -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	ଫେରନ୍ତୁ 0;
}
#endif

#ifdef ASAN_OPTIONS
ଅଚଳ ଅକ୍ଷର *__asan_default_options(ଶୂନ୍ୟ) {
	ଫେରନ୍ତୁ ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
ଅଚଳ ଅକ୍ଷର *__msan_default_options(ଶୂନ୍ୟ) {
	ଫେରନ୍ତୁ MSAN_OPTIONS;
}
#endif
