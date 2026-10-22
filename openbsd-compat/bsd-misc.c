
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
#ᱵᱟᱝ
	ᱡᱩᱫᱤ (argv0 == NULL)
		ᱨᱩᱣᱟᱹᱲ ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	ᱡᱩᱫᱤ (p == NULL)
		p = argv0;
	ᱵᱟᱝ
		p++;
#endif
	ᱡᱩᱫᱤ ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	ᱨᱩᱣᱟᱹᱲ q;
}

#ifndef HAVE_SETLOGIN
puur_naa_nka setlogin(const var_na *name)
{
	ᱨᱩᱣᱟᱹᱲ (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
puur_naa_nka innetgr(const var_na *netgroup, const var_na *host,
	    const var_na *user, const var_na *domain)
{
	ᱨᱩᱣᱟᱹᱲ (0);
}
#endif /* HAVE_INNETGR */

#ᱡᱩᱫᱤ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
puur_naa_nka seteuid(uid_t euid)
{
	ᱨᱩᱣᱟᱹᱲ (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ᱡᱩᱫᱤ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
puur_naa_nka setegid(uid_t egid)
{
	ᱨᱩᱣᱟᱹᱲ(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ᱡᱩᱫᱤ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const var_na *strerror(puur_naa_nka e)
{
	extern puur_naa_nka sys_nerr;
	extern var_na *sys_errlist[];

	ᱡᱩᱫᱤ ((e >= 0) && (e < sys_nerr))
		ᱨᱩᱣᱟᱹᱲ (sys_errlist[e]);

	ᱨᱩᱣᱟᱹᱲ ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
puur_naa_nka utimes(const var_na *filename, sa_nracanaa timeval *tvp)
{
	sa_nracanaa utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	ᱨᱩᱣᱟᱹᱲ (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
puur_naa_nka
utimensat(puur_naa_nka fd, const var_na *path, const sa_nracanaa timespec times[2],
    puur_naa_nka flag)
{
	sa_nracanaa timeval tv[2];
# ifdef HAVE_FUTIMES
	puur_naa_nka ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	ᱡᱩᱫᱤ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ᱨᱩᱣᱟᱹᱲ -1;
	}
# ifndef HAVE_FUTIMES
	ᱨᱩᱣᱟᱹᱲ utimes(path, tv);
# ᱵᱟᱝ
#  ifdef O_NOFOLLOW
	ᱡᱩᱫᱤ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ᱡᱩᱫᱤ ((fd = open(path, oflags)) == -1)
		ᱨᱩᱣᱟᱹᱲ -1;
	ret = futimes(fd, tv);
	close(fd);
	ᱨᱩᱣᱟᱹᱲ ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
puur_naa_nka
dirfd(void *dir)
{
	errno = ENOSYS;
	ᱨᱩᱣᱟᱹᱲ -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
puur_naa_nka
fchownat(puur_naa_nka fd, const var_na *path, uid_t owner, gid_t group, puur_naa_nka flag)
{
	puur_naa_nka ret, oflags = O_WRONLY;

	ᱡᱩᱫᱤ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ᱨᱩᱣᱟᱹᱲ -1;
	}
# ifndef HAVE_FCHOWN
	ᱨᱩᱣᱟᱹᱲ chown(path, owner, group);
# ᱵᱟᱝ
#  ifdef O_NOFOLLOW
	ᱡᱩᱫᱤ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ᱡᱩᱫᱤ ((fd = open(path, oflags)) == -1)
		ᱨᱩᱣᱟᱹᱲ -1;
	ret = fchown(fd, owner, group);
	close(fd);
	ᱨᱩᱣᱟᱹᱲ ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
puur_naa_nka
fchmodat(puur_naa_nka fd, const var_na *path, mode_t mode, puur_naa_nka flag)
{
	puur_naa_nka ret, oflags = O_WRONLY;

	ᱡᱩᱫᱤ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ᱨᱩᱣᱟᱹᱲ -1;
	}
# ifndef HAVE_FCHMOD
	ᱨᱩᱣᱟᱹᱲ chmod(path, mode);
# ᱵᱟᱝ
#  ifdef O_NOFOLLOW
	ᱡᱩᱫᱤ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ᱡᱩᱫᱤ ((fd = open(path, oflags)) == -1)
		ᱨᱩᱣᱟᱹᱲ -1;
	ret = fchmod(fd, mode);
	close(fd);
	ᱨᱩᱣᱟᱹᱲ ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
puur_naa_nka
fstatat(puur_naa_nka dirfd, const var_na *path, sa_nracanaa stat *sb, puur_naa_nka flag)
{
	ᱡᱩᱫᱤ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ᱨᱩᱣᱟᱹᱲ -1;
	}
	ᱡᱩᱫᱤ (flag == 0)
		ᱨᱩᱣᱟᱹᱲ stat(path, sb);
	ᱵᱟᱝ ᱡᱩᱫᱤ (flag == AT_SYMLINK_NOFOLLOW)
		ᱨᱩᱣᱟᱹᱲ lstat(path, sb);
	errno = ENOSYS;
	ᱨᱩᱣᱟᱹᱲ -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
puur_naa_nka
unlinkat(puur_naa_nka dirfd, const var_na *path, puur_naa_nka flag)
{
	ᱡᱩᱫᱤ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ᱨᱩᱣᱟᱹᱲ -1;
	}
	ᱡᱩᱫᱤ (flag == 0)
		ᱨᱩᱣᱟᱹᱲ unlink(path);
	errno = ENOSYS;
	ᱨᱩᱣᱟᱹᱲ -1;
}
#endif

#ifndef HAVE_TRUNCATE
puur_naa_nka truncate(const var_na *path, off_t length)
{
	puur_naa_nka fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	ᱡᱩᱫᱤ (fd < 0)
		ᱨᱩᱣᱟᱹᱲ (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	ᱡᱩᱫᱤ (ret == -1)
		errno = saverrno;

	ᱨᱩᱣᱟᱹᱲ(ret);
}
#endif /* HAVE_TRUNCATE */

#ᱡᱩᱫᱤ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
puur_naa_nka nanosleep(const sa_nracanaa timespec *req, sa_nracanaa timespec *rem)
{
	puur_naa_nka rc, saverrno;
	extern puur_naa_nka errno;
	sa_nracanaa timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	ᱡᱩᱫᱤ (rc == -1) {
		saverrno = errno;
		(void) gettimeofday (&tstop, NULL);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} ᱵᱟᱝ {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	ᱡᱩᱫᱤ (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	ᱨᱩᱣᱟᱹᱲ(rc);
}
#endif

#ᱡᱩᱫᱤ !defined(HAVE_USLEEP)
puur_naa_nka usleep(unsigned puur_naa_nka useconds)
{
	sa_nracanaa timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	ᱨᱩᱣᱟᱹᱲ nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(puur_naa_nka fd)
{
	puur_naa_nka ctty_pgrp;

	ᱡᱩᱫᱤ (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		ᱨᱩᱣᱟᱹᱲ(-1);
	ᱵᱟᱝ
		ᱨᱩᱣᱟᱹᱲ(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
puur_naa_nka
tcsendbreak(puur_naa_nka fd, puur_naa_nka duration)
{
# ᱡᱩᱫᱤ defined(TIOCSBRK) && defined(TIOCCBRK)
	sa_nracanaa timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	ᱡᱩᱫᱤ (ioctl(fd, TIOCSBRK, 0) == -1)
		ᱨᱩᱣᱟᱹᱲ (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	ᱡᱩᱫᱤ (ioctl(fd, TIOCCBRK, 0) == -1)
		ᱨᱩᱣᱟᱹᱲ (-1);
	ᱨᱩᱣᱟᱹᱲ (0);
# ᱵᱟᱝ
	ᱨᱩᱣᱟᱹᱲ -1;
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
	ᱡᱩᱫᱤ (cp != NULL)
		ᱨᱩᱣᱟᱹᱲ(memcpy(cp, str, len));
	ᱨᱩᱣᱟᱹᱲ NULL;
}
#endif

#ifndef HAVE_ISBLANK
puur_naa_nka
isblank(puur_naa_nka c)
{
	ᱨᱩᱣᱟᱹᱲ (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#ᱡᱩᱫᱤ defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	ᱨᱩᱣᱟᱹᱲ getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	ᱡᱩᱫᱤ (pid == 0)
		ᱨᱩᱣᱟᱹᱲ getpgrp();
#endif

	errno = ESRCH;
	ᱨᱩᱣᱟᱹᱲ -1;
}
#endif

#ifndef HAVE_PLEDGE
puur_naa_nka
pledge(const var_na *promises, const var_na *execpromises)
{
	ᱨᱩᱣᱟᱹᱲ 0;
}
#endif

#ifndef HAVE_UNVEIL
puur_naa_nka
unveil(const var_na *path, const var_na *permissions)
{
	ᱨᱩᱣᱟᱹᱲ 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
puur_naa_nka
mbtowc(wchar_t *pwc, const var_na *s, size_t n)
{
	ᱡᱩᱫᱤ (s == NULL || *s == '\0')
		ᱨᱩᱣᱟᱹᱲ 0;	/* ASCII is not state-dependent */
	ᱡᱩᱫᱤ (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		ᱨᱩᱣᱟᱹᱲ -1;
	}
	ᱡᱩᱫᱤ (pwc != NULL)
		*pwc = *s;
	ᱨᱩᱣᱟᱹᱲ 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	ᱨᱩᱣᱟᱹᱲ (j < 0 ? -j : j);
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
puur_naa_nka
raise(puur_naa_nka sig)
{
	ᱨᱩᱣᱟᱹᱲ kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	ᱨᱩᱣᱟᱹᱲ -1;
}
#endif

#ifndef HAVE_KILLPG
puur_naa_nka
killpg(pid_t pgrp, puur_naa_nka sig)
{
	ᱨᱩᱣᱟᱹᱲ kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
puur_naa_nka _ssh_compat_fflush(FILE *f)
{
	puur_naa_nka r1, r2;

	ᱡᱩᱫᱤ (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		ᱡᱩᱫᱤ (r1 == -1 || r2 == -1)
			ᱨᱩᱣᱟᱹᱲ -1;
		ᱨᱩᱣᱟᱹᱲ 0;
	}
	ᱨᱩᱣᱟᱹᱲ fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
sa_nracanaa tm *
localtime_r(const time_t *timep, sa_nracanaa tm *result)
{
	sa_nracanaa tm *tm = localtime(timep);
	*result = *tm;
	ᱨᱩᱣᱟᱹᱲ result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
puur_naa_nka
clock_gettime(clockid_t clockid, sa_nracanaa timespec *ts)
{
	sa_nracanaa timeval tv;

	ᱡᱩᱫᱤ (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		ᱨᱩᱣᱟᱹᱲ -1;
	}
	ᱡᱩᱫᱤ (ts == NULL) {
		errno = EFAULT;
		ᱨᱩᱣᱟᱹᱲ -1;
	}

	ᱡᱩᱫᱤ (gettimeofday(&tv, NULL) == -1)
		ᱨᱩᱣᱟᱹᱲ -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	ᱨᱩᱣᱟᱹᱲ 0;
}
#endif

#ifdef ASAN_OPTIONS
const var_na *__asan_default_options(void) {
	ᱨᱩᱣᱟᱹᱲ ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const var_na *__msan_default_options(void) {
	ᱨᱩᱣᱟᱹᱲ MSAN_OPTIONS;
}
#endif
