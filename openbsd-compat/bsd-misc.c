
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
#නැතහොත්
	නම් (argv0 == NULL)
		ආපසු ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	නම් (p == NULL)
		p = argv0;
	නැතහොත්
		p++;
#endif
	නම් ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	ආපසු q;
}

#ifndef HAVE_SETLOGIN
පූර්ණ_සංඛ්‍යා setlogin(const var_na *name)
{
	ආපසු (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
පූර්ණ_සංඛ්‍යා innetgr(const var_na *netgroup, const var_na *host,
	    const var_na *user, const var_na *domain)
{
	ආපසු (0);
}
#endif /* HAVE_INNETGR */

#නම් !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
පූර්ණ_සංඛ්‍යා seteuid(uid_t euid)
{
	ආපසු (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#නම් !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
පූර්ණ_සංඛ්‍යා setegid(uid_t egid)
{
	ආපසු(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#නම් !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const var_na *strerror(පූර්ණ_සංඛ්‍යා e)
{
	extern පූර්ණ_සංඛ්‍යා sys_nerr;
	extern var_na *sys_errlist[];

	නම් ((e >= 0) && (e < sys_nerr))
		ආපසු (sys_errlist[e]);

	ආපසු ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
පූර්ණ_සංඛ්‍යා utimes(const var_na *filename, sa_nracanaa timeval *tvp)
{
	sa_nracanaa utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	ආපසු (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
පූර්ණ_සංඛ්‍යා
utimensat(පූර්ණ_සංඛ්‍යා fd, const var_na *path, const sa_nracanaa timespec times[2],
    පූර්ණ_සංඛ්‍යා flag)
{
	sa_nracanaa timeval tv[2];
# ifdef HAVE_FUTIMES
	පූර්ණ_සංඛ්‍යා ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	නම් (fd != AT_FDCWD) {
		errno = ENOSYS;
		ආපසු -1;
	}
# ifndef HAVE_FUTIMES
	ආපසු utimes(path, tv);
# නැතහොත්
#  ifdef O_NOFOLLOW
	නම් (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	නම් ((fd = open(path, oflags)) == -1)
		ආපසු -1;
	ret = futimes(fd, tv);
	close(fd);
	ආපසු ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
පූර්ණ_සංඛ්‍යා
dirfd(void *dir)
{
	errno = ENOSYS;
	ආපසු -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
පූර්ණ_සංඛ්‍යා
fchownat(පූර්ණ_සංඛ්‍යා fd, const var_na *path, uid_t owner, gid_t group, පූර්ණ_සංඛ්‍යා flag)
{
	පූර්ණ_සංඛ්‍යා ret, oflags = O_WRONLY;

	නම් (fd != AT_FDCWD) {
		errno = ENOSYS;
		ආපසු -1;
	}
# ifndef HAVE_FCHOWN
	ආපසු chown(path, owner, group);
# නැතහොත්
#  ifdef O_NOFOLLOW
	නම් (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	නම් ((fd = open(path, oflags)) == -1)
		ආපසු -1;
	ret = fchown(fd, owner, group);
	close(fd);
	ආපසු ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
පූර්ණ_සංඛ්‍යා
fchmodat(පූර්ණ_සංඛ්‍යා fd, const var_na *path, mode_t mode, පූර්ණ_සංඛ්‍යා flag)
{
	පූර්ණ_සංඛ්‍යා ret, oflags = O_WRONLY;

	නම් (fd != AT_FDCWD) {
		errno = ENOSYS;
		ආපසු -1;
	}
# ifndef HAVE_FCHMOD
	ආපසු chmod(path, mode);
# නැතහොත්
#  ifdef O_NOFOLLOW
	නම් (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	නම් ((fd = open(path, oflags)) == -1)
		ආපසු -1;
	ret = fchmod(fd, mode);
	close(fd);
	ආපසු ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
පූර්ණ_සංඛ්‍යා
fstatat(පූර්ණ_සංඛ්‍යා dirfd, const var_na *path, sa_nracanaa stat *sb, පූර්ණ_සංඛ්‍යා flag)
{
	නම් (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ආපසු -1;
	}
	නම් (flag == 0)
		ආපසු stat(path, sb);
	නැතහොත් නම් (flag == AT_SYMLINK_NOFOLLOW)
		ආපසු lstat(path, sb);
	errno = ENOSYS;
	ආපසු -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
පූර්ණ_සංඛ්‍යා
unlinkat(පූර්ණ_සංඛ්‍යා dirfd, const var_na *path, පූර්ණ_සංඛ්‍යා flag)
{
	නම් (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ආපසු -1;
	}
	නම් (flag == 0)
		ආපසු unlink(path);
	errno = ENOSYS;
	ආපසු -1;
}
#endif

#ifndef HAVE_TRUNCATE
පූර්ණ_සංඛ්‍යා truncate(const var_na *path, off_t length)
{
	පූර්ණ_සංඛ්‍යා fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	නම් (fd < 0)
		ආපසු (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	නම් (ret == -1)
		errno = saverrno;

	ආපසු(ret);
}
#endif /* HAVE_TRUNCATE */

#නම් !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
පූර්ණ_සංඛ්‍යා nanosleep(const sa_nracanaa timespec *req, sa_nracanaa timespec *rem)
{
	පූර්ණ_සංඛ්‍යා rc, saverrno;
	extern පූර්ණ_සංඛ්‍යා errno;
	sa_nracanaa timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	නම් (rc == -1) {
		saverrno = errno;
		(void) gettimeofday (&tstop, NULL);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} නැතහොත් {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	නම් (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	ආපසු(rc);
}
#endif

#නම් !defined(HAVE_USLEEP)
පූර්ණ_සංඛ්‍යා usleep(unsigned පූර්ණ_සංඛ්‍යා useconds)
{
	sa_nracanaa timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	ආපසු nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(පූර්ණ_සංඛ්‍යා fd)
{
	පූර්ණ_සංඛ්‍යා ctty_pgrp;

	නම් (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		ආපසු(-1);
	නැතහොත්
		ආපසු(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
පූර්ණ_සංඛ්‍යා
tcsendbreak(පූර්ණ_සංඛ්‍යා fd, පූර්ණ_සංඛ්‍යා duration)
{
# නම් defined(TIOCSBRK) && defined(TIOCCBRK)
	sa_nracanaa timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	නම් (ioctl(fd, TIOCSBRK, 0) == -1)
		ආපසු (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	නම් (ioctl(fd, TIOCCBRK, 0) == -1)
		ආපසු (-1);
	ආපසු (0);
# නැතහොත්
	ආපසු -1;
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
	නම් (cp != NULL)
		ආපසු(memcpy(cp, str, len));
	ආපසු NULL;
}
#endif

#ifndef HAVE_ISBLANK
පූර්ණ_සංඛ්‍යා
isblank(පූර්ණ_සංඛ්‍යා c)
{
	ආපසු (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#නම් defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	ආපසු getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	නම් (pid == 0)
		ආපසු getpgrp();
#endif

	errno = ESRCH;
	ආපසු -1;
}
#endif

#ifndef HAVE_PLEDGE
පූර්ණ_සංඛ්‍යා
pledge(const var_na *promises, const var_na *execpromises)
{
	ආපසු 0;
}
#endif

#ifndef HAVE_UNVEIL
පූර්ණ_සංඛ්‍යා
unveil(const var_na *path, const var_na *permissions)
{
	ආපසු 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
පූර්ණ_සංඛ්‍යා
mbtowc(wchar_t *pwc, const var_na *s, size_t n)
{
	නම් (s == NULL || *s == '\0')
		ආපසු 0;	/* ASCII is not state-dependent */
	නම් (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		ආපසු -1;
	}
	නම් (pwc != NULL)
		*pwc = *s;
	ආපසු 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	ආපසු (j < 0 ? -j : j);
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
පූර්ණ_සංඛ්‍යා
raise(පූර්ණ_සංඛ්‍යා sig)
{
	ආපසු kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	ආපසු -1;
}
#endif

#ifndef HAVE_KILLPG
පූර්ණ_සංඛ්‍යා
killpg(pid_t pgrp, පූර්ණ_සංඛ්‍යා sig)
{
	ආපසු kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
පූර්ණ_සංඛ්‍යා _ssh_compat_fflush(FILE *f)
{
	පූර්ණ_සංඛ්‍යා r1, r2;

	නම් (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		නම් (r1 == -1 || r2 == -1)
			ආපසු -1;
		ආපසු 0;
	}
	ආපසු fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
sa_nracanaa tm *
localtime_r(const time_t *timep, sa_nracanaa tm *result)
{
	sa_nracanaa tm *tm = localtime(timep);
	*result = *tm;
	ආපසු result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
පූර්ණ_සංඛ්‍යා
clock_gettime(clockid_t clockid, sa_nracanaa timespec *ts)
{
	sa_nracanaa timeval tv;

	නම් (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		ආපසු -1;
	}
	නම් (ts == NULL) {
		errno = EFAULT;
		ආපසු -1;
	}

	නම් (gettimeofday(&tv, NULL) == -1)
		ආපසු -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	ආපසු 0;
}
#endif

#ifdef ASAN_OPTIONS
const var_na *__asan_default_options(void) {
	ආපසු ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const var_na *__msan_default_options(void) {
	ආපසු MSAN_OPTIONS;
}
#endif
