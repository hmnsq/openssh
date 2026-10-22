
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
#မဟုတ်ပါက
	အကယ်၍ (argv0 == NULL)
		ပြန်ပေး ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	အကယ်၍ (p == NULL)
		p = argv0;
	မဟုတ်ပါက
		p++;
#endif
	အကယ်၍ ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}
	ပြန်ပေး q;
}

#ifndef HAVE_SETLOGIN
ကိန်းပြည့် setlogin(const var_na *name)
{
	ပြန်ပေး (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
ကိန်းပြည့် innetgr(const var_na *netgroup, const var_na *host,
	    const var_na *user, const var_na *domain)
{
	ပြန်ပေး (0);
}
#endif /* HAVE_INNETGR */

#အကယ်၍ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
ကိန်းပြည့် seteuid(uid_t euid)
{
	ပြန်ပေး (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#အကယ်၍ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
ကိန်းပြည့် setegid(uid_t egid)
{
	ပြန်ပေး(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#အကယ်၍ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const var_na *strerror(ကိန်းပြည့် e)
{
	extern ကိန်းပြည့် sys_nerr;
	extern var_na *sys_errlist[];

	အကယ်၍ ((e >= 0) && (e < sys_nerr))
		ပြန်ပေး (sys_errlist[e]);

	ပြန်ပေး ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
ကိန်းပြည့် utimes(const var_na *filename, sa_nracanaa timeval *tvp)
{
	sa_nracanaa utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	ပြန်ပေး (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ကိန်းပြည့်
utimensat(ကိန်းပြည့် fd, const var_na *path, const sa_nracanaa timespec times[2],
    ကိန်းပြည့် flag)
{
	sa_nracanaa timeval tv[2];
# ifdef HAVE_FUTIMES
	ကိန်းပြည့် ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	အကယ်၍ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ပြန်ပေး -1;
	}
# ifndef HAVE_FUTIMES
	ပြန်ပေး utimes(path, tv);
# မဟုတ်ပါက
#  ifdef O_NOFOLLOW
	အကယ်၍ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	အကယ်၍ ((fd = open(path, oflags)) == -1)
		ပြန်ပေး -1;
	ret = futimes(fd, tv);
	close(fd);
	ပြန်ပေး ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
ကိန်းပြည့်
dirfd(void *dir)
{
	errno = ENOSYS;
	ပြန်ပေး -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ကိန်းပြည့်
fchownat(ကိန်းပြည့် fd, const var_na *path, uid_t owner, gid_t group, ကိန်းပြည့် flag)
{
	ကိန်းပြည့် ret, oflags = O_WRONLY;

	အကယ်၍ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ပြန်ပေး -1;
	}
# ifndef HAVE_FCHOWN
	ပြန်ပေး chown(path, owner, group);
# မဟုတ်ပါက
#  ifdef O_NOFOLLOW
	အကယ်၍ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	အကယ်၍ ((fd = open(path, oflags)) == -1)
		ပြန်ပေး -1;
	ret = fchown(fd, owner, group);
	close(fd);
	ပြန်ပေး ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ကိန်းပြည့်
fchmodat(ကိန်းပြည့် fd, const var_na *path, mode_t mode, ကိန်းပြည့် flag)
{
	ကိန်းပြည့် ret, oflags = O_WRONLY;

	အကယ်၍ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ပြန်ပေး -1;
	}
# ifndef HAVE_FCHMOD
	ပြန်ပေး chmod(path, mode);
# မဟုတ်ပါက
#  ifdef O_NOFOLLOW
	အကယ်၍ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	အကယ်၍ ((fd = open(path, oflags)) == -1)
		ပြန်ပေး -1;
	ret = fchmod(fd, mode);
	close(fd);
	ပြန်ပေး ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
ကိန်းပြည့်
fstatat(ကိန်းပြည့် dirfd, const var_na *path, sa_nracanaa stat *sb, ကိန်းပြည့် flag)
{
	အကယ်၍ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ပြန်ပေး -1;
	}
	အကယ်၍ (flag == 0)
		ပြန်ပေး stat(path, sb);
	မဟုတ်ပါက အကယ်၍ (flag == AT_SYMLINK_NOFOLLOW)
		ပြန်ပေး lstat(path, sb);
	errno = ENOSYS;
	ပြန်ပေး -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
ကိန်းပြည့်
unlinkat(ကိန်းပြည့် dirfd, const var_na *path, ကိန်းပြည့် flag)
{
	အကယ်၍ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		ပြန်ပေး -1;
	}
	အကယ်၍ (flag == 0)
		ပြန်ပေး unlink(path);
	errno = ENOSYS;
	ပြန်ပေး -1;
}
#endif

#ifndef HAVE_TRUNCATE
ကိန်းပြည့် truncate(const var_na *path, off_t length)
{
	ကိန်းပြည့် fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	အကယ်၍ (fd < 0)
		ပြန်ပေး (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	အကယ်၍ (ret == -1)
		errno = saverrno;

	ပြန်ပေး(ret);
}
#endif /* HAVE_TRUNCATE */

#အကယ်၍ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
ကိန်းပြည့် nanosleep(const sa_nracanaa timespec *req, sa_nracanaa timespec *rem)
{
	ကိန်းပြည့် rc, saverrno;
	extern ကိန်းပြည့် errno;
	sa_nracanaa timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	အကယ်၍ (rc == -1) {
		saverrno = errno;
		(void) gettimeofday (&tstop, NULL);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} မဟုတ်ပါက {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	အကယ်၍ (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	ပြန်ပေး(rc);
}
#endif

#အကယ်၍ !defined(HAVE_USLEEP)
ကိန်းပြည့် usleep(unsigned ကိန်းပြည့် useconds)
{
	sa_nracanaa timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	ပြန်ပေး nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(ကိန်းပြည့် fd)
{
	ကိန်းပြည့် ctty_pgrp;

	အကယ်၍ (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		ပြန်ပေး(-1);
	မဟုတ်ပါက
		ပြန်ပေး(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
ကိန်းပြည့်
tcsendbreak(ကိန်းပြည့် fd, ကိန်းပြည့် duration)
{
# အကယ်၍ defined(TIOCSBRK) && defined(TIOCCBRK)
	sa_nracanaa timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	အကယ်၍ (ioctl(fd, TIOCSBRK, 0) == -1)
		ပြန်ပေး (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	အကယ်၍ (ioctl(fd, TIOCCBRK, 0) == -1)
		ပြန်ပေး (-1);
	ပြန်ပေး (0);
# မဟုတ်ပါက
	ပြန်ပေး -1;
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
	အကယ်၍ (cp != NULL)
		ပြန်ပေး(memcpy(cp, str, len));
	ပြန်ပေး NULL;
}
#endif

#ifndef HAVE_ISBLANK
ကိန်းပြည့်
isblank(ကိန်းပြည့် c)
{
	ပြန်ပေး (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#အကယ်၍ defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	ပြန်ပေး getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	အကယ်၍ (pid == 0)
		ပြန်ပေး getpgrp();
#endif

	errno = ESRCH;
	ပြန်ပေး -1;
}
#endif

#ifndef HAVE_PLEDGE
ကိန်းပြည့်
pledge(const var_na *promises, const var_na *execpromises)
{
	ပြန်ပေး 0;
}
#endif

#ifndef HAVE_UNVEIL
ကိန်းပြည့်
unveil(const var_na *path, const var_na *permissions)
{
	ပြန်ပေး 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
ကိန်းပြည့်
mbtowc(wchar_t *pwc, const var_na *s, size_t n)
{
	အကယ်၍ (s == NULL || *s == '\0')
		ပြန်ပေး 0;	/* ASCII is not state-dependent */
	အကယ်၍ (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		ပြန်ပေး -1;
	}
	အကယ်၍ (pwc != NULL)
		*pwc = *s;
	ပြန်ပေး 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	ပြန်ပေး (j < 0 ? -j : j);
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
ကိန်းပြည့်
raise(ကိန်းပြည့် sig)
{
	ပြန်ပေး kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	ပြန်ပေး -1;
}
#endif

#ifndef HAVE_KILLPG
ကိန်းပြည့်
killpg(pid_t pgrp, ကိန်းပြည့် sig)
{
	ပြန်ပေး kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
ကိန်းပြည့် _ssh_compat_fflush(FILE *f)
{
	ကိန်းပြည့် r1, r2;

	အကယ်၍ (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		အကယ်၍ (r1 == -1 || r2 == -1)
			ပြန်ပေး -1;
		ပြန်ပေး 0;
	}
	ပြန်ပေး fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
sa_nracanaa tm *
localtime_r(const time_t *timep, sa_nracanaa tm *result)
{
	sa_nracanaa tm *tm = localtime(timep);
	*result = *tm;
	ပြန်ပေး result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
ကိန်းပြည့်
clock_gettime(clockid_t clockid, sa_nracanaa timespec *ts)
{
	sa_nracanaa timeval tv;

	အကယ်၍ (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		ပြန်ပေး -1;
	}
	အကယ်၍ (ts == NULL) {
		errno = EFAULT;
		ပြန်ပေး -1;
	}

	အကယ်၍ (gettimeofday(&tv, NULL) == -1)
		ပြန်ပေး -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	ပြန်ပေး 0;
}
#endif

#ifdef ASAN_OPTIONS
const var_na *__asan_default_options(void) {
	ပြန်ပေး ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
const var_na *__msan_default_options(void) {
	ပြန်ပေး MSAN_OPTIONS;
}
#endif
