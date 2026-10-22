
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
#ᮜᮤᮚ
	ᮚᮦᮔ᮪ (argv0 == NULL)
		ᮝᮜᮤ ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	ᮚᮦᮔ᮪ (p == NULL)
		p = argv0;
	ᮜᮤᮚ
		p++;
#endif
	ᮚᮦᮔ᮪ ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	ᮝᮜᮤ q;
}

#ifndef HAVE_SETLOGIN
puur_naa_nka setlogin(const var_na *name)
{
	ᮝᮜᮤ (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
puur_naa_nka innetgr(const var_na *netgroup, const var_na *host,
	    const var_na *user, const var_na *domain)
{
	ᮝᮜᮤ (0);
}
#endif /* HAVE_INNETGR */

#ᮚᮦᮔ᮪ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
puur_naa_nka seteuid(uid_t euid)
{
	ᮝᮜᮤ (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ᮚᮦᮔ᮪ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
puur_naa_nka setegid(uid_t egid)
{
	ᮝᮜᮤ(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ᮚᮦᮔ᮪ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const var_na *strerror(puur_naa_nka e)
{
	extern puur_naa_nka sys_nerr;
	extern var_na *sys_errlist[];

	ᮚᮦᮔ᮪ ((e >= 0) && (e < sys_nerr))
		ᮝᮜᮤ (sys_errlist[e]);

	ᮝᮜᮤ ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
puur_naa_nka utimes(const var_na *filename, sa_nracanaa timeval *tvp)
{
	sa_nracanaa utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	ᮝᮜᮤ (utime(filename, &ub));
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

	ᮚᮦᮔ᮪ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ᮝᮜᮤ -1;
	}
# ifndef HAVE_FUTIMES
	ᮝᮜᮤ utimes(path, tv);
# ᮜᮤᮚ
#  ifdef O_NOFOLLOW
	ᮚᮦᮔ᮪ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ᮚᮦᮔ᮪ ((fd = open(path, oflags)) == -1)
		ᮝᮜᮤ -1;
	ret = futimes(fd, tv);
	close(fd);
	ᮝᮜᮤ ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
puur_naa_nka
dirfd(void *dir)
{
	errno = ENOSYS;
	ᮝᮜᮤ -1;
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

	ᮚᮦᮔ᮪ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ᮝᮜᮤ -1;
	}
# ifndef HAVE_FCHOWN
	ᮝᮜᮤ chown(path, owner, group);
# ᮜᮤᮚ
#  ifdef O_NOFOLLOW
	ᮚᮦᮔ᮪ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ᮚᮦᮔ᮪ ((fd = open(path, oflags)) == -1)
		ᮝᮜᮤ -1;
	ret = fchown(fd, owner, group);
	close(fd);
	ᮝᮜᮤ ret;
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

	ᮚᮦᮔ᮪ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ᮝᮜᮤ -1;
	}
# ifndef HAVE_FCHMOD
	ᮝᮜᮤ chmod(path, mode);
# ᮜᮤᮚ
#  ifdef O_NOFOLLOW
	ᮚᮦᮔ᮪ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ᮚᮦᮔ᮪ ((fd = open(path, oflags)) == -1)
		ᮝᮜᮤ -1;
	ret = fchmod(fd, mode);
	close(fd);
	ᮝᮜᮤ ret;
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
	ᮚᮦᮔ᮪ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ᮝᮜᮤ -1;
	}
	ᮚᮦᮔ᮪ (flag == 0)
		ᮝᮜᮤ stat(path, sb);
	ᮜᮤᮚ ᮚᮦᮔ᮪ (flag == AT_SYMLINK_NOFOLLOW)
		ᮝᮜᮤ lstat(path, sb);
	errno = ENOSYS;
	ᮝᮜᮤ -1;
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
	ᮚᮦᮔ᮪ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ᮝᮜᮤ -1;
	}
	ᮚᮦᮔ᮪ (flag == 0)
		ᮝᮜᮤ unlink(path);
	errno = ENOSYS;
	ᮝᮜᮤ -1;
}
#endif

#ifndef HAVE_TRUNCATE
puur_naa_nka truncate(const var_na *path, off_t length)
{
	puur_naa_nka fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	ᮚᮦᮔ᮪ (fd < 0)
		ᮝᮜᮤ (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	ᮚᮦᮔ᮪ (ret == -1)
		errno = saverrno;

	ᮝᮜᮤ(ret);
}
#endif /* HAVE_TRUNCATE */

#ᮚᮦᮔ᮪ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
puur_naa_nka nanosleep(const sa_nracanaa timespec *req, sa_nracanaa timespec *rem)
{
	puur_naa_nka rc, saverrno;
	extern puur_naa_nka errno;
	sa_nracanaa timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	ᮚᮦᮔ᮪ (rc == -1) {
		saverrno = errno;
		(void) gettimeofday (&tstop, NULL);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} ᮜᮤᮚ {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	ᮚᮦᮔ᮪ (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	ᮝᮜᮤ(rc);
}
#endif

#ᮚᮦᮔ᮪ !defined(HAVE_USLEEP)
puur_naa_nka usleep(unsigned puur_naa_nka useconds)
{
	sa_nracanaa timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	ᮝᮜᮤ nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(puur_naa_nka fd)
{
	puur_naa_nka ctty_pgrp;

	ᮚᮦᮔ᮪ (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		ᮝᮜᮤ(-1);
	ᮜᮤᮚ
		ᮝᮜᮤ(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
puur_naa_nka
tcsendbreak(puur_naa_nka fd, puur_naa_nka duration)
{
# ᮚᮦᮔ᮪ defined(TIOCSBRK) && defined(TIOCCBRK)
	sa_nracanaa timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	ᮚᮦᮔ᮪ (ioctl(fd, TIOCSBRK, 0) == -1)
		ᮝᮜᮤ (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	ᮚᮦᮔ᮪ (ioctl(fd, TIOCCBRK, 0) == -1)
		ᮝᮜᮤ (-1);
	ᮝᮜᮤ (0);
# ᮜᮤᮚ
	ᮝᮜᮤ -1;
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
	ᮚᮦᮔ᮪ (cp != NULL)
		ᮝᮜᮤ(memcpy(cp, str, len));
	ᮝᮜᮤ NULL;
}
#endif

#ifndef HAVE_ISBLANK
puur_naa_nka
isblank(puur_naa_nka c)
{
	ᮝᮜᮤ (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#ᮚᮦᮔ᮪ defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	ᮝᮜᮤ getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	ᮚᮦᮔ᮪ (pid == 0)
		ᮝᮜᮤ getpgrp();
#endif

	errno = ESRCH;
	ᮝᮜᮤ -1;
}
#endif

#ifndef HAVE_PLEDGE
puur_naa_nka
pledge(const var_na *promises, const var_na *execpromises)
{
	ᮝᮜᮤ 0;
}
#endif

#ifndef HAVE_UNVEIL
puur_naa_nka
unveil(const var_na *path, const var_na *permissions)
{
	ᮝᮜᮤ 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
puur_naa_nka
mbtowc(wchar_t *pwc, const var_na *s, size_t n)
{
	ᮚᮦᮔ᮪ (s == NULL || *s == '\0')
		ᮝᮜᮤ 0;	/* ASCII is not state-dependent */
	ᮚᮦᮔ᮪ (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		ᮝᮜᮤ -1;
	}
	ᮚᮦᮔ᮪ (pwc != NULL)
		*pwc = *s;
	ᮝᮜᮤ 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	ᮝᮜᮤ (j < 0 ? -j : j);
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
	ᮝᮜᮤ kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	ᮝᮜᮤ -1;
}
#endif

#ifndef HAVE_KILLPG
puur_naa_nka
killpg(pid_t pgrp, puur_naa_nka sig)
{
	ᮝᮜᮤ kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
puur_naa_nka _ssh_compat_fflush(FILE *f)
{
	puur_naa_nka r1, r2;

	ᮚᮦᮔ᮪ (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		ᮚᮦᮔ᮪ (r1 == -1 || r2 == -1)
			ᮝᮜᮤ -1;
		ᮝᮜᮤ 0;
	}
	ᮝᮜᮤ fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
sa_nracanaa tm *
localtime_r(const time_t *timep, sa_nracanaa tm *result)
{
	sa_nracanaa tm *tm = localtime(timep);
	*result = *tm;
	ᮝᮜᮤ result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
puur_naa_nka
clock_gettime(clockid_t clockid, sa_nracanaa timespec *ts)
{
	sa_nracanaa timeval tv;

	ᮚᮦᮔ᮪ (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		ᮝᮜᮤ -1;
	}
	ᮚᮦᮔ᮪ (ts == NULL) {
		errno = EFAULT;
		ᮝᮜᮤ -1;
	}

	ᮚᮦᮔ᮪ (gettimeofday(&tv, NULL) == -1)
		ᮝᮜᮤ -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	ᮝᮜᮤ 0;
}
#endif

#ifdef ASAN_OPTIONS
const var_na *__asan_default_options(void) {
	ᮝᮜᮤ ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const var_na *__msan_default_options(void) {
	ᮝᮜᮤ MSAN_OPTIONS;
}
#endif
