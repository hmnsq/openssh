
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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/ioctl.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_SELECT_H
# include <sys/select.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE___PROGNAME
ਅੱਖਰ *__progname;
#ਜੇ_ਅੰਤ

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
ਅੱਖਰ *ssh_get_progname(ਅੱਖਰ *argv0)
{
	ਅੱਖਰ *p, *q;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE___PROGNAME
	ਬਾਹਰੀ ਅੱਖਰ *__progname;

	p = __progname;
#ਨਹੀਂਤਾਂ
	ਜੇ (argv0 == ਨਿਰਾ)
		ਵਾਪਸ ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	ਜੇ (p == ਨਿਰਾ)
		p = argv0;
	ਨਹੀਂਤਾਂ
		p++;
#ਜੇ_ਅੰਤ
	ਜੇ ((q = strdup(p)) == ਨਿਰਾ) {
		perror("strdup");
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	ਵਾਪਸ q;
}

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SETLOGIN
ਪੂਰਨ setlogin(ਅਚਲ ਅੱਖਰ *name)
{
	ਵਾਪਸ (0);
}
#ਜੇ_ਅੰਤ /* !HAVE_SETLOGIN */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_INNETGR
ਪੂਰਨ innetgr(ਅਚਲ ਅੱਖਰ *netgroup, ਅਚਲ ਅੱਖਰ *host,
	    ਅਚਲ ਅੱਖਰ *user, ਅਚਲ ਅੱਖਰ *domain)
{
	ਵਾਪਸ (0);
}
#ਜੇ_ਅੰਤ /* HAVE_INNETGR */

#ਜੇ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
ਪੂਰਨ seteuid(uid_t euid)
{
	ਵਾਪਸ (setreuid(-1, euid));
}
#ਜੇ_ਅੰਤ /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ਜੇ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
ਪੂਰਨ setegid(uid_t egid)
{
	ਵਾਪਸ(setresgid(-1, egid, -1));
}
#ਜੇ_ਅੰਤ /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ਜੇ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ਅਚਲ ਅੱਖਰ *strerror(ਪੂਰਨ e)
{
	ਬਾਹਰੀ ਪੂਰਨ sys_nerr;
	ਬਾਹਰੀ ਅੱਖਰ *sys_errlist[];

	ਜੇ ((e >= 0) && (e < sys_nerr))
		ਵਾਪਸ (sys_errlist[e]);

	ਵਾਪਸ ("unlisted error");
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_UTIMES
ਪੂਰਨ utimes(ਅਚਲ ਅੱਖਰ *filename, ਬਣਤਰ timeval *tvp)
{
	ਬਣਤਰ utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	ਵਾਪਸ (utime(filename, &ub));
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ਪੂਰਨ
utimensat(ਪੂਰਨ fd, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅਚਲ ਬਣਤਰ timespec times[2],
    ਪੂਰਨ flag)
{
	ਬਣਤਰ timeval tv[2];
# ifdef HAVE_FUTIMES
	ਪੂਰਨ ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	ਜੇ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ਵਾਪਸ -1;
	}
# ifndef HAVE_FUTIMES
	ਵਾਪਸ utimes(ਰਸਤਾ, tv);
# ਨਹੀਂਤਾਂ
#  ifdef O_NOFOLLOW
	ਜੇ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ਜੇ ((fd = open(ਰਸਤਾ, oflags)) == -1)
		ਵਾਪਸ -1;
	ret = futimes(fd, tv);
	close(fd);
	ਵਾਪਸ ret;
# endif
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_DIRFD
ਪੂਰਨ
dirfd(ਖਾਲੀ *dir)
{
	errno = ENOSYS;
	ਵਾਪਸ -1;
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ਪੂਰਨ
fchownat(ਪੂਰਨ fd, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, uid_t owner, gid_t ਸਮੂਹ, ਪੂਰਨ flag)
{
	ਪੂਰਨ ret, oflags = O_WRONLY;

	ਜੇ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ਵਾਪਸ -1;
	}
# ifndef HAVE_FCHOWN
	ਵਾਪਸ chown(ਰਸਤਾ, owner, ਸਮੂਹ);
# ਨਹੀਂਤਾਂ
#  ifdef O_NOFOLLOW
	ਜੇ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ਜੇ ((fd = open(ਰਸਤਾ, oflags)) == -1)
		ਵਾਪਸ -1;
	ret = fchown(fd, owner, ਸਮੂਹ);
	close(fd);
	ਵਾਪਸ ret;
# endif
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ਪੂਰਨ
fchmodat(ਪੂਰਨ fd, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਬਹੁਲਕ_t ਬਹੁਲਕ, ਪੂਰਨ flag)
{
	ਪੂਰਨ ret, oflags = O_WRONLY;

	ਜੇ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ਵਾਪਸ -1;
	}
# ifndef HAVE_FCHMOD
	ਵਾਪਸ chmod(ਰਸਤਾ, ਬਹੁਲਕ);
# ਨਹੀਂਤਾਂ
#  ifdef O_NOFOLLOW
	ਜੇ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ਜੇ ((fd = open(ਰਸਤਾ, oflags)) == -1)
		ਵਾਪਸ -1;
	ret = fchmod(fd, ਬਹੁਲਕ);
	close(fd);
	ਵਾਪਸ ret;
# endif
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
ਪੂਰਨ
fstatat(ਪੂਰਨ dirfd, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਬਣਤਰ stat *sb, ਪੂਰਨ flag)
{
	ਜੇ (dirfd != AT_FDCWD && ਰਸਤਾ && ਰਸਤਾ[0] != '/') {
		errno = ENOSYS;
		ਵਾਪਸ -1;
	}
	ਜੇ (flag == 0)
		ਵਾਪਸ stat(ਰਸਤਾ, sb);
	ਨਹੀਂਤਾਂ ਜੇ (flag == AT_SYMLINK_NOFOLLOW)
		ਵਾਪਸ lstat(ਰਸਤਾ, sb);
	errno = ENOSYS;
	ਵਾਪਸ -1;
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
ਪੂਰਨ
unlinkat(ਪੂਰਨ dirfd, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ flag)
{
	ਜੇ (dirfd != AT_FDCWD && ਰਸਤਾ && ਰਸਤਾ[0] != '/') {
		errno = ENOSYS;
		ਵਾਪਸ -1;
	}
	ਜੇ (flag == 0)
		ਵਾਪਸ unlink(ਰਸਤਾ);
	errno = ENOSYS;
	ਵਾਪਸ -1;
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_TRUNCATE
ਪੂਰਨ truncate(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, off_t ਲੰਮਾਈ)
{
	ਪੂਰਨ fd, ret, saverrno;

	fd = open(ਰਸਤਾ, O_WRONLY);
	ਜੇ (fd < 0)
		ਵਾਪਸ (-1);

	ret = ftruncate(fd, ਲੰਮਾਈ);
	saverrno = errno;
	close(fd);
	ਜੇ (ret == -1)
		errno = saverrno;

	ਵਾਪਸ(ret);
}
#ਜੇ_ਅੰਤ /* HAVE_TRUNCATE */

#ਜੇ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
ਪੂਰਨ nanosleep(ਅਚਲ ਬਣਤਰ timespec *req, ਬਣਤਰ timespec *rem)
{
	ਪੂਰਨ rc, saverrno;
	ਬਾਹਰੀ ਪੂਰਨ errno;
	ਬਣਤਰ timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_ਮੰਜ਼ਿਲ_TIMEVAL(&time2wait, req)
	(ਖਾਲੀ) gettimeofday(&tstart, ਨਿਰਾ);
	rc = select(0, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, &time2wait);
	ਜੇ (rc == -1) {
		saverrno = errno;
		(ਖਾਲੀ) gettimeofday (&tstop, ਨਿਰਾ);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} ਨਹੀਂਤਾਂ {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	ਜੇ (rem != ਨਿਰਾ)
		TIMEVAL_ਮੰਜ਼ਿਲ_TIMESPEC(&tremain, rem)

	ਵਾਪਸ(rc);
}
#ਜੇ_ਅੰਤ

#ਜੇ !defined(HAVE_USLEEP)
ਪੂਰਨ usleep(ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ useconds)
{
	ਬਣਤਰ timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	ਵਾਪਸ nanosleep(&ts, ਨਿਰਾ);
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_TCGETPGRP
pid_t
tcgetpgrp(ਪੂਰਨ fd)
{
	ਪੂਰਨ ctty_pgrp;

	ਜੇ (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		ਵਾਪਸ(-1);
	ਨਹੀਂਤਾਂ
		ਵਾਪਸ(ctty_pgrp);
}
#ਜੇ_ਅੰਤ /* HAVE_TCGETPGRP */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_TCSENDBREAK
ਪੂਰਨ
tcsendbreak(ਪੂਰਨ fd, ਪੂਰਨ duration)
{
# ਜੇ defined(TIOCSBRK) && defined(TIOCCBRK)
	ਬਣਤਰ timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	ਜੇ (ioctl(fd, TIOCSBRK, 0) == -1)
		ਵਾਪਸ (-1);
	(ਖਾਲੀ)select(0, 0, 0, 0, &sleepytime);
	ਜੇ (ioctl(fd, TIOCCBRK, 0) == -1)
		ਵਾਪਸ (-1);
	ਵਾਪਸ (0);
# ਨਹੀਂਤਾਂ
	ਵਾਪਸ -1;
# endif
}
#ਜੇ_ਅੰਤ /* HAVE_TCSENDBREAK */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRDUP
ਅੱਖਰ *
strdup(ਅਚਲ ਅੱਖਰ *str)
{
	ਮਾਪ_t len;
	ਅੱਖਰ *cp;

	len = ਲੜੀ_ਲੰਬਾਈ(str) + 1;
	cp = ਸਮ੍ਰਿਤੀ_ਦਿਓ(len);
	ਜੇ (cp != ਨਿਰਾ)
		ਵਾਪਸ(ਸਮ੍ਰਿਤੀ_ਨਕਲ(cp, str, len));
	ਵਾਪਸ ਨਿਰਾ;
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ISBLANK
ਪੂਰਨ
isblank(ਪੂਰਨ c)
{
	ਵਾਪਸ (c == ' ' || c == '\t');
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#ਜੇ defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	ਵਾਪਸ getpgrp(pid);
#ਜਾਂਜੇ defined(HAVE_GETPGRP)
	ਜੇ (pid == 0)
		ਵਾਪਸ getpgrp();
#ਜੇ_ਅੰਤ

	errno = ESRCH;
	ਵਾਪਸ -1;
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_PLEDGE
ਪੂਰਨ
pledge(ਅਚਲ ਅੱਖਰ *promises, ਅਚਲ ਅੱਖਰ *execpromises)
{
	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_UNVEIL
ਪੂਰਨ
unveil(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *permissions)
{
	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
ਪੂਰਨ
mbtowc(wchar_t *pwc, ਅਚਲ ਅੱਖਰ *s, ਮਾਪ_t n)
{
	ਜੇ (s == ਨਿਰਾ || *s == '\0')
		ਵਾਪਸ 0;	/* ASCII is not state-dependent */
	ਜੇ (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		ਵਾਪਸ -1;
	}
	ਜੇ (pwc != ਨਿਰਾ)
		*pwc = *s;
	ਵਾਪਸ 1;
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_LLABS
ਲੰਮਾ ਲੰਮਾ
llabs(ਲੰਮਾ ਲੰਮਾ j)
{
	ਵਾਪਸ (j < 0 ? -j : j);
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_BZERO
ਖਾਲੀ
bzero(ਖਾਲੀ *b, ਮਾਪ_t n)
{
	(ਖਾਲੀ)memset(b, 0, n);
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_RAISE
ਪੂਰਨ
ਉਠਾਓ(ਪੂਰਨ sig)
{
	ਵਾਪਸ kill(getpid(), sig);
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	ਵਾਪਸ -1;
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_KILLPG
ਪੂਰਨ
killpg(pid_t pgrp, ਪੂਰਨ sig)
{
	ਵਾਪਸ kill(pgrp, sig);
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ FFLUSH_NULL_BUG
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ fflush
ਪੂਰਨ _ssh_compat_fflush(FILE *f)
{
	ਪੂਰਨ r1, r2;

	ਜੇ (f == ਨਿਰਾ) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		ਜੇ (r1 == -1 || r2 == -1)
			ਵਾਪਸ -1;
		ਵਾਪਸ 0;
	}
	ਵਾਪਸ fflush(f);
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_LOCALTIME_R
ਬਣਤਰ tm *
localtime_r(ਅਚਲ time_t *timep, ਬਣਤਰ tm *ਨਤੀਜਾ)
{
	ਬਣਤਰ tm *tm = localtime(timep);
	*ਨਤੀਜਾ = *tm;
	ਵਾਪਸ ਨਤੀਜਾ;
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_CLOCK_GETTIME
ਪੂਰਨ
clock_gettime(clockid_t clockid, ਬਣਤਰ timespec *ts)
{
	ਬਣਤਰ timeval tv;

	ਜੇ (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		ਵਾਪਸ -1;
	}
	ਜੇ (ts == ਨਿਰਾ) {
		errno = EFAULT;
		ਵਾਪਸ -1;
	}

	ਜੇ (gettimeofday(&tv, ਨਿਰਾ) == -1)
		ਵਾਪਸ -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (ਲੰਮਾ)tv.tv_usec * 1000;
	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ASAN_OPTIONS
ਅਚਲ ਅੱਖਰ *__asan_default_options(ਖਾਲੀ) {
	ਵਾਪਸ ASAN_OPTIONS;
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ MSAN_OPTIONS
ਅਚਲ ਅੱਖਰ *__msan_default_options(ਖਾਲੀ) {
	ਵਾਪਸ MSAN_OPTIONS;
}
#ਜੇ_ਅੰਤ
