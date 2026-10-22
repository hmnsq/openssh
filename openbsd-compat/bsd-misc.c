
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
#ပေႃးဢမ်ႇ
	ပေႃး (argv0 == NULL)
		ပွၵ်ႈ ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	ပေႃး (p == NULL)
		p = argv0;
	ပေႃးဢမ်ႇ
		p++;
#endif
	ပေႃး ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	ပွၵ်ႈ q;
}

#ifndef HAVE_SETLOGIN
puur_naa_nka setlogin(const var_na *name)
{
	ပွၵ်ႈ (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
puur_naa_nka innetgr(const var_na *netgroup, const var_na *host,
	    const var_na *user, const var_na *domain)
{
	ပွၵ်ႈ (0);
}
#endif /* HAVE_INNETGR */

#ပေႃး !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
puur_naa_nka seteuid(uid_t euid)
{
	ပွၵ်ႈ (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ပေႃး !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
puur_naa_nka setegid(uid_t egid)
{
	ပွၵ်ႈ(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ပေႃး !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const var_na *strerror(puur_naa_nka e)
{
	extern puur_naa_nka sys_nerr;
	extern var_na *sys_errlist[];

	ပေႃး ((e >= 0) && (e < sys_nerr))
		ပွၵ်ႈ (sys_errlist[e]);

	ပွၵ်ႈ ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
puur_naa_nka utimes(const var_na *filename, sa_nracanaa timeval *tvp)
{
	sa_nracanaa utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	ပွၵ်ႈ (utime(filename, &ub));
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

	ပေႃး (fd != AT_FDCWD) {
		errno = ENOSYS;
		ပွၵ်ႈ -1;
	}
# ifndef HAVE_FUTIMES
	ပွၵ်ႈ utimes(path, tv);
# ပေႃးဢမ်ႇ
#  ifdef O_NOFOLLOW
	ပေႃး (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ပေႃး ((fd = open(path, oflags)) == -1)
		ပွၵ်ႈ -1;
	ret = futimes(fd, tv);
	close(fd);
	ပွၵ်ႈ ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
puur_naa_nka
dirfd(void *dir)
{
	errno = ENOSYS;
	ပွၵ်ႈ -1;
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

	ပေႃး (fd != AT_FDCWD) {
		errno = ENOSYS;
		ပွၵ်ႈ -1;
	}
# ifndef HAVE_FCHOWN
	ပွၵ်ႈ chown(path, owner, group);
# ပေႃးဢမ်ႇ
#  ifdef O_NOFOLLOW
	ပေႃး (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ပေႃး ((fd = open(path, oflags)) == -1)
		ပွၵ်ႈ -1;
	ret = fchown(fd, owner, group);
	close(fd);
	ပွၵ်ႈ ret;
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

	ပေႃး (fd != AT_FDCWD) {
		errno = ENOSYS;
		ပွၵ်ႈ -1;
	}
# ifndef HAVE_FCHMOD
	ပွၵ်ႈ chmod(path, mode);
# ပေႃးဢမ်ႇ
#  ifdef O_NOFOLLOW
	ပေႃး (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ပေႃး ((fd = open(path, oflags)) == -1)
		ပွၵ်ႈ -1;
	ret = fchmod(fd, mode);
	close(fd);
	ပွၵ်ႈ ret;
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
	ပေႃး (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ပွၵ်ႈ -1;
	}
	ပေႃး (flag == 0)
		ပွၵ်ႈ stat(path, sb);
	ပေႃးဢမ်ႇ ပေႃး (flag == AT_SYMLINK_NOFOLLOW)
		ပွၵ်ႈ lstat(path, sb);
	errno = ENOSYS;
	ပွၵ်ႈ -1;
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
	ပေႃး (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ပွၵ်ႈ -1;
	}
	ပေႃး (flag == 0)
		ပွၵ်ႈ unlink(path);
	errno = ENOSYS;
	ပွၵ်ႈ -1;
}
#endif

#ifndef HAVE_TRUNCATE
puur_naa_nka truncate(const var_na *path, off_t length)
{
	puur_naa_nka fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	ပေႃး (fd < 0)
		ပွၵ်ႈ (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	ပေႃး (ret == -1)
		errno = saverrno;

	ပွၵ်ႈ(ret);
}
#endif /* HAVE_TRUNCATE */

#ပေႃး !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
puur_naa_nka nanosleep(const sa_nracanaa timespec *req, sa_nracanaa timespec *rem)
{
	puur_naa_nka rc, saverrno;
	extern puur_naa_nka errno;
	sa_nracanaa timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	ပေႃး (rc == -1) {
		saverrno = errno;
		(void) gettimeofday (&tstop, NULL);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} ပေႃးဢမ်ႇ {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	ပေႃး (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	ပွၵ်ႈ(rc);
}
#endif

#ပေႃး !defined(HAVE_USLEEP)
puur_naa_nka usleep(unsigned puur_naa_nka useconds)
{
	sa_nracanaa timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	ပွၵ်ႈ nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(puur_naa_nka fd)
{
	puur_naa_nka ctty_pgrp;

	ပေႃး (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		ပွၵ်ႈ(-1);
	ပေႃးဢမ်ႇ
		ပွၵ်ႈ(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
puur_naa_nka
tcsendbreak(puur_naa_nka fd, puur_naa_nka duration)
{
# ပေႃး defined(TIOCSBRK) && defined(TIOCCBRK)
	sa_nracanaa timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	ပေႃး (ioctl(fd, TIOCSBRK, 0) == -1)
		ပွၵ်ႈ (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	ပေႃး (ioctl(fd, TIOCCBRK, 0) == -1)
		ပွၵ်ႈ (-1);
	ပွၵ်ႈ (0);
# ပေႃးဢမ်ႇ
	ပွၵ်ႈ -1;
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
	ပေႃး (cp != NULL)
		ပွၵ်ႈ(memcpy(cp, str, len));
	ပွၵ်ႈ NULL;
}
#endif

#ifndef HAVE_ISBLANK
puur_naa_nka
isblank(puur_naa_nka c)
{
	ပွၵ်ႈ (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#ပေႃး defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	ပွၵ်ႈ getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	ပေႃး (pid == 0)
		ပွၵ်ႈ getpgrp();
#endif

	errno = ESRCH;
	ပွၵ်ႈ -1;
}
#endif

#ifndef HAVE_PLEDGE
puur_naa_nka
pledge(const var_na *promises, const var_na *execpromises)
{
	ပွၵ်ႈ 0;
}
#endif

#ifndef HAVE_UNVEIL
puur_naa_nka
unveil(const var_na *path, const var_na *permissions)
{
	ပွၵ်ႈ 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
puur_naa_nka
mbtowc(wchar_t *pwc, const var_na *s, size_t n)
{
	ပေႃး (s == NULL || *s == '\0')
		ပွၵ်ႈ 0;	/* ASCII is not state-dependent */
	ပေႃး (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		ပွၵ်ႈ -1;
	}
	ပေႃး (pwc != NULL)
		*pwc = *s;
	ပွၵ်ႈ 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	ပွၵ်ႈ (j < 0 ? -j : j);
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
	ပွၵ်ႈ kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	ပွၵ်ႈ -1;
}
#endif

#ifndef HAVE_KILLPG
puur_naa_nka
killpg(pid_t pgrp, puur_naa_nka sig)
{
	ပွၵ်ႈ kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
puur_naa_nka _ssh_compat_fflush(FILE *f)
{
	puur_naa_nka r1, r2;

	ပေႃး (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		ပေႃး (r1 == -1 || r2 == -1)
			ပွၵ်ႈ -1;
		ပွၵ်ႈ 0;
	}
	ပွၵ်ႈ fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
sa_nracanaa tm *
localtime_r(const time_t *timep, sa_nracanaa tm *result)
{
	sa_nracanaa tm *tm = localtime(timep);
	*result = *tm;
	ပွၵ်ႈ result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
puur_naa_nka
clock_gettime(clockid_t clockid, sa_nracanaa timespec *ts)
{
	sa_nracanaa timeval tv;

	ပေႃး (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		ပွၵ်ႈ -1;
	}
	ပေႃး (ts == NULL) {
		errno = EFAULT;
		ပွၵ်ႈ -1;
	}

	ပေႃး (gettimeofday(&tv, NULL) == -1)
		ပွၵ်ႈ -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	ပွၵ်ႈ 0;
}
#endif

#ifdef ASAN_OPTIONS
const var_na *__asan_default_options(void) {
	ပွၵ်ႈ ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const var_na *__msan_default_options(void) {
	ပွၵ်ႈ MSAN_OPTIONS;
}
#endif
