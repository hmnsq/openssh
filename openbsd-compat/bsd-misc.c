
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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/ioctl.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#અન્તર્ભાવ <sys/time.h>

#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <unistd.h>

#ifndef HAVE___PROGNAME
અક્ષર *__progname;
#endif

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
અક્ષર *ssh_get_progname(અક્ષર *argv0)
{
	અક્ષર *p, *q;
#ifdef HAVE___PROGNAME
	બાહ્ય અક્ષર *__progname;

	p = __progname;
#નહીંતર
	જો (argv0 == ખાલી)
		પાછા ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	જો (p == ખાલી)
		p = argv0;
	નહીંતર
		p++;
#endif
	જો ((q = strdup(p)) == ખાલી) {
		perror("strdup");
		exit(1);
	}
	પાછા q;
}

#ifndef HAVE_SETLOGIN
પૂર્ણાંક setlogin(અચલ અક્ષર *name)
{
	પાછા (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
પૂર્ણાંક innetgr(અચલ અક્ષર *netgroup, અચલ અક્ષર *host,
	    અચલ અક્ષર *user, અચલ અક્ષર *domain)
{
	પાછા (0);
}
#endif /* HAVE_INNETGR */

#જો !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
પૂર્ણાંક seteuid(uid_t euid)
{
	પાછા (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#જો !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
પૂર્ણાંક setegid(uid_t egid)
{
	પાછા(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#જો !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
અચલ અક્ષર *strerror(પૂર્ણાંક e)
{
	બાહ્ય પૂર્ણાંક sys_nerr;
	બાહ્ય અક્ષર *sys_errlist[];

	જો ((e >= 0) && (e < sys_nerr))
		પાછા (sys_errlist[e]);

	પાછા ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
પૂર્ણાંક utimes(અચલ અક્ષર *filename, સંરચના timeval *tvp)
{
	સંરચના utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	પાછા (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
પૂર્ણાંક
utimensat(પૂર્ણાંક fd, અચલ અક્ષર *path, અચલ સંરચના timespec times[2],
    પૂર્ણાંક flag)
{
	સંરચના timeval tv[2];
# ifdef HAVE_FUTIMES
	પૂર્ણાંક ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	જો (fd != AT_FDCWD) {
		errno = ENOSYS;
		પાછા -1;
	}
# ifndef HAVE_FUTIMES
	પાછા utimes(path, tv);
# નહીંતર
#  ifdef O_NOFOLLOW
	જો (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	જો ((fd = open(path, oflags)) == -1)
		પાછા -1;
	ret = futimes(fd, tv);
	close(fd);
	પાછા ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
પૂર્ણાંક
dirfd(શૂન્ય *dir)
{
	errno = ENOSYS;
	પાછા -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
પૂર્ણાંક
fchownat(પૂર્ણાંક fd, અચલ અક્ષર *path, uid_t owner, gid_t group, પૂર્ણાંક flag)
{
	પૂર્ણાંક ret, oflags = O_WRONLY;

	જો (fd != AT_FDCWD) {
		errno = ENOSYS;
		પાછા -1;
	}
# ifndef HAVE_FCHOWN
	પાછા chown(path, owner, group);
# નહીંતર
#  ifdef O_NOFOLLOW
	જો (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	જો ((fd = open(path, oflags)) == -1)
		પાછા -1;
	ret = fchown(fd, owner, group);
	close(fd);
	પાછા ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
પૂર્ણાંક
fchmodat(પૂર્ણાંક fd, અચલ અક્ષર *path, mode_t mode, પૂર્ણાંક flag)
{
	પૂર્ણાંક ret, oflags = O_WRONLY;

	જો (fd != AT_FDCWD) {
		errno = ENOSYS;
		પાછા -1;
	}
# ifndef HAVE_FCHMOD
	પાછા chmod(path, mode);
# નહીંતર
#  ifdef O_NOFOLLOW
	જો (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	જો ((fd = open(path, oflags)) == -1)
		પાછા -1;
	ret = fchmod(fd, mode);
	close(fd);
	પાછા ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
પૂર્ણાંક
fstatat(પૂર્ણાંક dirfd, અચલ અક્ષર *path, સંરચના stat *sb, પૂર્ણાંક flag)
{
	જો (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		પાછા -1;
	}
	જો (flag == 0)
		પાછા stat(path, sb);
	નહીંતર જો (flag == AT_SYMLINK_NOFOLLOW)
		પાછા lstat(path, sb);
	errno = ENOSYS;
	પાછા -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
પૂર્ણાંક
unlinkat(પૂર્ણાંક dirfd, અચલ અક્ષર *path, પૂર્ણાંક flag)
{
	જો (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		પાછા -1;
	}
	જો (flag == 0)
		પાછા unlink(path);
	errno = ENOSYS;
	પાછા -1;
}
#endif

#ifndef HAVE_TRUNCATE
પૂર્ણાંક truncate(અચલ અક્ષર *path, off_t length)
{
	પૂર્ણાંક fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	જો (fd < 0)
		પાછા (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	જો (ret == -1)
		errno = saverrno;

	પાછા(ret);
}
#endif /* HAVE_TRUNCATE */

#જો !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
પૂર્ણાંક nanosleep(અચલ સંરચના timespec *req, સંરચના timespec *rem)
{
	પૂર્ણાંક rc, saverrno;
	બાહ્ય પૂર્ણાંક errno;
	સંરચના timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(શૂન્ય) gettimeofday(&tstart, ખાલી);
	rc = select(0, ખાલી, ખાલી, ખાલી, &time2wait);
	જો (rc == -1) {
		saverrno = errno;
		(શૂન્ય) gettimeofday (&tstop, ખાલી);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} નહીંતર {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	જો (rem != ખાલી)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	પાછા(rc);
}
#endif

#જો !defined(HAVE_USLEEP)
પૂર્ણાંક usleep(unsigned પૂર્ણાંક useconds)
{
	સંરચના timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	પાછા nanosleep(&ts, ખાલી);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(પૂર્ણાંક fd)
{
	પૂર્ણાંક ctty_pgrp;

	જો (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		પાછા(-1);
	નહીંતર
		પાછા(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
પૂર્ણાંક
tcsendbreak(પૂર્ણાંક fd, પૂર્ણાંક duration)
{
# જો defined(TIOCSBRK) && defined(TIOCCBRK)
	સંરચના timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	જો (ioctl(fd, TIOCSBRK, 0) == -1)
		પાછા (-1);
	(શૂન્ય)select(0, 0, 0, 0, &sleepytime);
	જો (ioctl(fd, TIOCCBRK, 0) == -1)
		પાછા (-1);
	પાછા (0);
# નહીંતર
	પાછા -1;
# endif
}
#endif /* HAVE_TCSENDBREAK */

#ifndef HAVE_STRDUP
અક્ષર *
strdup(અચલ અક્ષર *str)
{
	size_t len;
	અક્ષર *cp;

	len = strlen(str) + 1;
	cp = malloc(len);
	જો (cp != ખાલી)
		પાછા(memcpy(cp, str, len));
	પાછા ખાલી;
}
#endif

#ifndef HAVE_ISBLANK
પૂર્ણાંક
isblank(પૂર્ણાંક c)
{
	પાછા (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#જો defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	પાછા getpgrp(pid);
#અથવાજો defined(HAVE_GETPGRP)
	જો (pid == 0)
		પાછા getpgrp();
#endif

	errno = ESRCH;
	પાછા -1;
}
#endif

#ifndef HAVE_PLEDGE
પૂર્ણાંક
pledge(અચલ અક્ષર *promises, અચલ અક્ષર *execpromises)
{
	પાછા 0;
}
#endif

#ifndef HAVE_UNVEIL
પૂર્ણાંક
unveil(અચલ અક્ષર *path, અચલ અક્ષર *permissions)
{
	પાછા 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
પૂર્ણાંક
mbtowc(wchar_t *pwc, અચલ અક્ષર *s, size_t n)
{
	જો (s == ખાલી || *s == '\0')
		પાછા 0;	/* ASCII is not state-dependent */
	જો (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		પાછા -1;
	}
	જો (pwc != ખાલી)
		*pwc = *s;
	પાછા 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	પાછા (j < 0 ? -j : j);
}
#endif

#ifndef HAVE_BZERO
શૂન્ય
bzero(શૂન્ય *b, size_t n)
{
	(શૂન્ય)memset(b, 0, n);
}
#endif

#ifndef HAVE_RAISE
પૂર્ણાંક
ઉઠાવો(પૂર્ણાંક sig)
{
	પાછા kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	પાછા -1;
}
#endif

#ifndef HAVE_KILLPG
પૂર્ણાંક
killpg(pid_t pgrp, પૂર્ણાંક sig)
{
	પાછા kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
પૂર્ણાંક _ssh_compat_fflush(FILE *f)
{
	પૂર્ણાંક r1, r2;

	જો (f == ખાલી) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		જો (r1 == -1 || r2 == -1)
			પાછા -1;
		પાછા 0;
	}
	પાછા fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
સંરચના tm *
localtime_r(અચલ time_t *timep, સંરચના tm *result)
{
	સંરચના tm *tm = localtime(timep);
	*result = *tm;
	પાછા result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
પૂર્ણાંક
clock_gettime(clockid_t clockid, સંરચના timespec *ts)
{
	સંરચના timeval tv;

	જો (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		પાછા -1;
	}
	જો (ts == ખાલી) {
		errno = EFAULT;
		પાછા -1;
	}

	જો (gettimeofday(&tv, ખાલી) == -1)
		પાછા -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	પાછા 0;
}
#endif

#ifdef ASAN_OPTIONS
અચલ અક્ષર *__asan_default_options(શૂન્ય) {
	પાછા ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
અચલ અક્ષર *__msan_default_options(શૂન્ય) {
	પાછા MSAN_OPTIONS;
}
#endif
