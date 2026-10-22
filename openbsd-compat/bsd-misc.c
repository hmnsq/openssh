
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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/ioctl.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#അന്തര്ഭാവ <sys/time.h>

#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <unistd.h>

#ifndef HAVE___PROGNAME
അക്ഷരം *__progname;
#endif

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
അക്ഷരം *ssh_get_progname(അക്ഷരം *argv0)
{
	അക്ഷരം *p, *q;
#ifdef HAVE___PROGNAME
	ബാഹ്യ അക്ഷരം *__progname;

	p = __progname;
#അല്ലെങ്കിൽ
	എങ്കിൽ (argv0 == ശൂന്യ)
		തിരികെ ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	എങ്കിൽ (p == ശൂന്യ)
		p = argv0;
	അല്ലെങ്കിൽ
		p++;
#endif
	എങ്കിൽ ((q = strdup(p)) == ശൂന്യ) {
		perror("strdup");
		exit(1);
	}
	തിരികെ q;
}

#ifndef HAVE_SETLOGIN
പൂർണ്ണസംഖ്യ setlogin(സ്ഥിരം അക്ഷരം *name)
{
	തിരികെ (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
പൂർണ്ണസംഖ്യ innetgr(സ്ഥിരം അക്ഷരം *netgroup, സ്ഥിരം അക്ഷരം *host,
	    സ്ഥിരം അക്ഷരം *user, സ്ഥിരം അക്ഷരം *domain)
{
	തിരികെ (0);
}
#endif /* HAVE_INNETGR */

#എങ്കിൽ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
പൂർണ്ണസംഖ്യ seteuid(uid_t euid)
{
	തിരികെ (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#എങ്കിൽ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
പൂർണ്ണസംഖ്യ setegid(uid_t egid)
{
	തിരികെ(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#എങ്കിൽ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
സ്ഥിരം അക്ഷരം *strerror(പൂർണ്ണസംഖ്യ e)
{
	ബാഹ്യ പൂർണ്ണസംഖ്യ sys_nerr;
	ബാഹ്യ അക്ഷരം *sys_errlist[];

	എങ്കിൽ ((e >= 0) && (e < sys_nerr))
		തിരികെ (sys_errlist[e]);

	തിരികെ ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
പൂർണ്ണസംഖ്യ utimes(സ്ഥിരം അക്ഷരം *filename, ഘടന timeval *tvp)
{
	ഘടന utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	തിരികെ (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
പൂർണ്ണസംഖ്യ
utimensat(പൂർണ്ണസംഖ്യ fd, സ്ഥിരം അക്ഷരം *path, സ്ഥിരം ഘടന timespec times[2],
    പൂർണ്ണസംഖ്യ flag)
{
	ഘടന timeval tv[2];
# ifdef HAVE_FUTIMES
	പൂർണ്ണസംഖ്യ ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	എങ്കിൽ (fd != AT_FDCWD) {
		errno = ENOSYS;
		തിരികെ -1;
	}
# ifndef HAVE_FUTIMES
	തിരികെ utimes(path, tv);
# അല്ലെങ്കിൽ
#  ifdef O_NOFOLLOW
	എങ്കിൽ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	എങ്കിൽ ((fd = open(path, oflags)) == -1)
		തിരികെ -1;
	ret = futimes(fd, tv);
	close(fd);
	തിരികെ ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
പൂർണ്ണസംഖ്യ
dirfd(ശൂന്യം *dir)
{
	errno = ENOSYS;
	തിരികെ -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
പൂർണ്ണസംഖ്യ
fchownat(പൂർണ്ണസംഖ്യ fd, സ്ഥിരം അക്ഷരം *path, uid_t owner, gid_t group, പൂർണ്ണസംഖ്യ flag)
{
	പൂർണ്ണസംഖ്യ ret, oflags = O_WRONLY;

	എങ്കിൽ (fd != AT_FDCWD) {
		errno = ENOSYS;
		തിരികെ -1;
	}
# ifndef HAVE_FCHOWN
	തിരികെ chown(path, owner, group);
# അല്ലെങ്കിൽ
#  ifdef O_NOFOLLOW
	എങ്കിൽ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	എങ്കിൽ ((fd = open(path, oflags)) == -1)
		തിരികെ -1;
	ret = fchown(fd, owner, group);
	close(fd);
	തിരികെ ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
പൂർണ്ണസംഖ്യ
fchmodat(പൂർണ്ണസംഖ്യ fd, സ്ഥിരം അക്ഷരം *path, mode_t mode, പൂർണ്ണസംഖ്യ flag)
{
	പൂർണ്ണസംഖ്യ ret, oflags = O_WRONLY;

	എങ്കിൽ (fd != AT_FDCWD) {
		errno = ENOSYS;
		തിരികെ -1;
	}
# ifndef HAVE_FCHMOD
	തിരികെ chmod(path, mode);
# അല്ലെങ്കിൽ
#  ifdef O_NOFOLLOW
	എങ്കിൽ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	എങ്കിൽ ((fd = open(path, oflags)) == -1)
		തിരികെ -1;
	ret = fchmod(fd, mode);
	close(fd);
	തിരികെ ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
പൂർണ്ണസംഖ്യ
fstatat(പൂർണ്ണസംഖ്യ dirfd, സ്ഥിരം അക്ഷരം *path, ഘടന stat *sb, പൂർണ്ണസംഖ്യ flag)
{
	എങ്കിൽ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		തിരികെ -1;
	}
	എങ്കിൽ (flag == 0)
		തിരികെ stat(path, sb);
	അല്ലെങ്കിൽ എങ്കിൽ (flag == AT_SYMLINK_NOFOLLOW)
		തിരികെ lstat(path, sb);
	errno = ENOSYS;
	തിരികെ -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
പൂർണ്ണസംഖ്യ
unlinkat(പൂർണ്ണസംഖ്യ dirfd, സ്ഥിരം അക്ഷരം *path, പൂർണ്ണസംഖ്യ flag)
{
	എങ്കിൽ (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		തിരികെ -1;
	}
	എങ്കിൽ (flag == 0)
		തിരികെ unlink(path);
	errno = ENOSYS;
	തിരികെ -1;
}
#endif

#ifndef HAVE_TRUNCATE
പൂർണ്ണസംഖ്യ truncate(സ്ഥിരം അക്ഷരം *path, off_t length)
{
	പൂർണ്ണസംഖ്യ fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	എങ്കിൽ (fd < 0)
		തിരികെ (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	എങ്കിൽ (ret == -1)
		errno = saverrno;

	തിരികെ(ret);
}
#endif /* HAVE_TRUNCATE */

#എങ്കിൽ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
പൂർണ്ണസംഖ്യ nanosleep(സ്ഥിരം ഘടന timespec *req, ഘടന timespec *rem)
{
	പൂർണ്ണസംഖ്യ rc, saverrno;
	ബാഹ്യ പൂർണ്ണസംഖ്യ errno;
	ഘടന timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(ശൂന്യം) gettimeofday(&tstart, ശൂന്യ);
	rc = select(0, ശൂന്യ, ശൂന്യ, ശൂന്യ, &time2wait);
	എങ്കിൽ (rc == -1) {
		saverrno = errno;
		(ശൂന്യം) gettimeofday (&tstop, ശൂന്യ);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} അല്ലെങ്കിൽ {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	എങ്കിൽ (rem != ശൂന്യ)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	തിരികെ(rc);
}
#endif

#എങ്കിൽ !defined(HAVE_USLEEP)
പൂർണ്ണസംഖ്യ usleep(unsigned പൂർണ്ണസംഖ്യ useconds)
{
	ഘടന timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	തിരികെ nanosleep(&ts, ശൂന്യ);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(പൂർണ്ണസംഖ്യ fd)
{
	പൂർണ്ണസംഖ്യ ctty_pgrp;

	എങ്കിൽ (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		തിരികെ(-1);
	അല്ലെങ്കിൽ
		തിരികെ(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
പൂർണ്ണസംഖ്യ
tcsendbreak(പൂർണ്ണസംഖ്യ fd, പൂർണ്ണസംഖ്യ duration)
{
# എങ്കിൽ defined(TIOCSBRK) && defined(TIOCCBRK)
	ഘടന timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	എങ്കിൽ (ioctl(fd, TIOCSBRK, 0) == -1)
		തിരികെ (-1);
	(ശൂന്യം)select(0, 0, 0, 0, &sleepytime);
	എങ്കിൽ (ioctl(fd, TIOCCBRK, 0) == -1)
		തിരികെ (-1);
	തിരികെ (0);
# അല്ലെങ്കിൽ
	തിരികെ -1;
# endif
}
#endif /* HAVE_TCSENDBREAK */

#ifndef HAVE_STRDUP
അക്ഷരം *
strdup(സ്ഥിരം അക്ഷരം *str)
{
	size_t len;
	അക്ഷരം *cp;

	len = strlen(str) + 1;
	cp = malloc(len);
	എങ്കിൽ (cp != ശൂന്യ)
		തിരികെ(memcpy(cp, str, len));
	തിരികെ ശൂന്യ;
}
#endif

#ifndef HAVE_ISBLANK
പൂർണ്ണസംഖ്യ
isblank(പൂർണ്ണസംഖ്യ c)
{
	തിരികെ (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#എങ്കിൽ defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	തിരികെ getpgrp(pid);
#അല്ലെങ്കിലെങ്കിൽ defined(HAVE_GETPGRP)
	എങ്കിൽ (pid == 0)
		തിരികെ getpgrp();
#endif

	errno = ESRCH;
	തിരികെ -1;
}
#endif

#ifndef HAVE_PLEDGE
പൂർണ്ണസംഖ്യ
pledge(സ്ഥിരം അക്ഷരം *promises, സ്ഥിരം അക്ഷരം *execpromises)
{
	തിരികെ 0;
}
#endif

#ifndef HAVE_UNVEIL
പൂർണ്ണസംഖ്യ
unveil(സ്ഥിരം അക്ഷരം *path, സ്ഥിരം അക്ഷരം *permissions)
{
	തിരികെ 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
പൂർണ്ണസംഖ്യ
mbtowc(wchar_t *pwc, സ്ഥിരം അക്ഷരം *s, size_t n)
{
	എങ്കിൽ (s == ശൂന്യ || *s == '\0')
		തിരികെ 0;	/* ASCII is not state-dependent */
	എങ്കിൽ (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		തിരികെ -1;
	}
	എങ്കിൽ (pwc != ശൂന്യ)
		*pwc = *s;
	തിരികെ 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	തിരികെ (j < 0 ? -j : j);
}
#endif

#ifndef HAVE_BZERO
ശൂന്യം
bzero(ശൂന്യം *b, size_t n)
{
	(ശൂന്യം)memset(b, 0, n);
}
#endif

#ifndef HAVE_RAISE
പൂർണ്ണസംഖ്യ
ഉയർത്തുക(പൂർണ്ണസംഖ്യ sig)
{
	തിരികെ kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	തിരികെ -1;
}
#endif

#ifndef HAVE_KILLPG
പൂർണ്ണസംഖ്യ
killpg(pid_t pgrp, പൂർണ്ണസംഖ്യ sig)
{
	തിരികെ kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
പൂർണ്ണസംഖ്യ _ssh_compat_fflush(FILE *f)
{
	പൂർണ്ണസംഖ്യ r1, r2;

	എങ്കിൽ (f == ശൂന്യ) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		എങ്കിൽ (r1 == -1 || r2 == -1)
			തിരികെ -1;
		തിരികെ 0;
	}
	തിരികെ fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
ഘടന tm *
localtime_r(സ്ഥിരം time_t *timep, ഘടന tm *result)
{
	ഘടന tm *tm = localtime(timep);
	*result = *tm;
	തിരികെ result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
പൂർണ്ണസംഖ്യ
clock_gettime(clockid_t clockid, ഘടന timespec *ts)
{
	ഘടന timeval tv;

	എങ്കിൽ (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		തിരികെ -1;
	}
	എങ്കിൽ (ts == ശൂന്യ) {
		errno = EFAULT;
		തിരികെ -1;
	}

	എങ്കിൽ (gettimeofday(&tv, ശൂന്യ) == -1)
		തിരികെ -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	തിരികെ 0;
}
#endif

#ifdef ASAN_OPTIONS
സ്ഥിരം അക്ഷരം *__asan_default_options(ശൂന്യം) {
	തിരികെ ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
സ്ഥിരം അക്ഷരം *__msan_default_options(ശൂന്യം) {
	തിരികെ MSAN_OPTIONS;
}
#endif
