
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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/ioctl.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#अन्तर्भाव <sys/time.h>

#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>

#ifndef HAVE___PROGNAME
वर्ण *__progname;
#endif

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
वर्ण *ssh_get_progname(वर्ण *argv0)
{
	वर्ण *p, *q;
#ifdef HAVE___PROGNAME
	बाह्य वर्ण *__progname;

	p = __progname;
#अञ्ञथा
	सचे (argv0 == रिक्त)
		पटिनिवत्त ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	सचे (p == रिक्त)
		p = argv0;
	अञ्ञथा
		p++;
#endif
	सचे ((q = strdup(p)) == रिक्त) {
		perror("strdup");
		exit(1);
	}
	पटिनिवत्त q;
}

#ifndef HAVE_SETLOGIN
पूर्णाङ्क setlogin(ध्रुव वर्ण *name)
{
	पटिनिवत्त (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
पूर्णाङ्क innetgr(ध्रुव वर्ण *netgroup, ध्रुव वर्ण *host,
	    ध्रुव वर्ण *user, ध्रुव वर्ण *domain)
{
	पटिनिवत्त (0);
}
#endif /* HAVE_INNETGR */

#सचे !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
पूर्णाङ्क seteuid(uid_t euid)
{
	पटिनिवत्त (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#सचे !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
पूर्णाङ्क setegid(uid_t egid)
{
	पटिनिवत्त(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#सचे !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ध्रुव वर्ण *strerror(पूर्णाङ्क e)
{
	बाह्य पूर्णाङ्क sys_nerr;
	बाह्य वर्ण *sys_errlist[];

	सचे ((e >= 0) && (e < sys_nerr))
		पटिनिवत्त (sys_errlist[e]);

	पटिनिवत्त ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
पूर्णाङ्क utimes(ध्रुव वर्ण *filename, संरचना timeval *tvp)
{
	संरचना utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	पटिनिवत्त (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
पूर्णाङ्क
utimensat(पूर्णाङ्क fd, ध्रुव वर्ण *path, ध्रुव संरचना timespec times[2],
    पूर्णाङ्क flag)
{
	संरचना timeval tv[2];
# ifdef HAVE_FUTIMES
	पूर्णाङ्क ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	सचे (fd != AT_FDCWD) {
		errno = ENOSYS;
		पटिनिवत्त -1;
	}
# ifndef HAVE_FUTIMES
	पटिनिवत्त utimes(path, tv);
# अञ्ञथा
#  ifdef O_NOFOLLOW
	सचे (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	सचे ((fd = open(path, oflags)) == -1)
		पटिनिवत्त -1;
	ret = futimes(fd, tv);
	close(fd);
	पटिनिवत्त ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
पूर्णाङ्क
dirfd(शून्य *dir)
{
	errno = ENOSYS;
	पटिनिवत्त -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
पूर्णाङ्क
fchownat(पूर्णाङ्क fd, ध्रुव वर्ण *path, uid_t owner, gid_t group, पूर्णाङ्क flag)
{
	पूर्णाङ्क ret, oflags = O_WRONLY;

	सचे (fd != AT_FDCWD) {
		errno = ENOSYS;
		पटिनिवत्त -1;
	}
# ifndef HAVE_FCHOWN
	पटिनिवत्त chown(path, owner, group);
# अञ्ञथा
#  ifdef O_NOFOLLOW
	सचे (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	सचे ((fd = open(path, oflags)) == -1)
		पटिनिवत्त -1;
	ret = fchown(fd, owner, group);
	close(fd);
	पटिनिवत्त ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
पूर्णाङ्क
fchmodat(पूर्णाङ्क fd, ध्रुव वर्ण *path, mode_t mode, पूर्णाङ्क flag)
{
	पूर्णाङ्क ret, oflags = O_WRONLY;

	सचे (fd != AT_FDCWD) {
		errno = ENOSYS;
		पटिनिवत्त -1;
	}
# ifndef HAVE_FCHMOD
	पटिनिवत्त chmod(path, mode);
# अञ्ञथा
#  ifdef O_NOFOLLOW
	सचे (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	सचे ((fd = open(path, oflags)) == -1)
		पटिनिवत्त -1;
	ret = fchmod(fd, mode);
	close(fd);
	पटिनिवत्त ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
पूर्णाङ्क
fstatat(पूर्णाङ्क dirfd, ध्रुव वर्ण *path, संरचना stat *sb, पूर्णाङ्क flag)
{
	सचे (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		पटिनिवत्त -1;
	}
	सचे (flag == 0)
		पटिनिवत्त stat(path, sb);
	अञ्ञथा सचे (flag == AT_SYMLINK_NOFOLLOW)
		पटिनिवत्त lstat(path, sb);
	errno = ENOSYS;
	पटिनिवत्त -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
पूर्णाङ्क
unlinkat(पूर्णाङ्क dirfd, ध्रुव वर्ण *path, पूर्णाङ्क flag)
{
	सचे (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		पटिनिवत्त -1;
	}
	सचे (flag == 0)
		पटिनिवत्त unlink(path);
	errno = ENOSYS;
	पटिनिवत्त -1;
}
#endif

#ifndef HAVE_TRUNCATE
पूर्णाङ्क truncate(ध्रुव वर्ण *path, off_t length)
{
	पूर्णाङ्क fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	सचे (fd < 0)
		पटिनिवत्त (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	सचे (ret == -1)
		errno = saverrno;

	पटिनिवत्त(ret);
}
#endif /* HAVE_TRUNCATE */

#सचे !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
पूर्णाङ्क nanosleep(ध्रुव संरचना timespec *req, संरचना timespec *rem)
{
	पूर्णाङ्क rc, saverrno;
	बाह्य पूर्णाङ्क errno;
	संरचना timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(शून्य) gettimeofday(&tstart, रिक्त);
	rc = select(0, रिक्त, रिक्त, रिक्त, &time2wait);
	सचे (rc == -1) {
		saverrno = errno;
		(शून्य) gettimeofday (&tstop, रिक्त);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} अञ्ञथा {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	सचे (rem != रिक्त)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	पटिनिवत्त(rc);
}
#endif

#सचे !defined(HAVE_USLEEP)
पूर्णाङ्क usleep(unsigned पूर्णाङ्क useconds)
{
	संरचना timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	पटिनिवत्त nanosleep(&ts, रिक्त);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(पूर्णाङ्क fd)
{
	पूर्णाङ्क ctty_pgrp;

	सचे (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		पटिनिवत्त(-1);
	अञ्ञथा
		पटिनिवत्त(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
पूर्णाङ्क
tcsendbreak(पूर्णाङ्क fd, पूर्णाङ्क duration)
{
# सचे defined(TIOCSBRK) && defined(TIOCCBRK)
	संरचना timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	सचे (ioctl(fd, TIOCSBRK, 0) == -1)
		पटिनिवत्त (-1);
	(शून्य)select(0, 0, 0, 0, &sleepytime);
	सचे (ioctl(fd, TIOCCBRK, 0) == -1)
		पटिनिवत्त (-1);
	पटिनिवत्त (0);
# अञ्ञथा
	पटिनिवत्त -1;
# endif
}
#endif /* HAVE_TCSENDBREAK */

#ifndef HAVE_STRDUP
वर्ण *
strdup(ध्रुव वर्ण *str)
{
	size_t len;
	वर्ण *cp;

	len = strlen(str) + 1;
	cp = malloc(len);
	सचे (cp != रिक्त)
		पटिनिवत्त(memcpy(cp, str, len));
	पटिनिवत्त रिक्त;
}
#endif

#ifndef HAVE_ISBLANK
पूर्णाङ्क
isblank(पूर्णाङ्क c)
{
	पटिनिवत्त (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#सचे defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	पटिनिवत्त getpgrp(pid);
#नोचेद्यदि defined(HAVE_GETPGRP)
	सचे (pid == 0)
		पटिनिवत्त getpgrp();
#endif

	errno = ESRCH;
	पटिनिवत्त -1;
}
#endif

#ifndef HAVE_PLEDGE
पूर्णाङ्क
pledge(ध्रुव वर्ण *promises, ध्रुव वर्ण *execpromises)
{
	पटिनिवत्त 0;
}
#endif

#ifndef HAVE_UNVEIL
पूर्णाङ्क
unveil(ध्रुव वर्ण *path, ध्रुव वर्ण *permissions)
{
	पटिनिवत्त 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
पूर्णाङ्क
mbtowc(wchar_t *pwc, ध्रुव वर्ण *s, size_t n)
{
	सचे (s == रिक्त || *s == '\0')
		पटिनिवत्त 0;	/* ASCII is not state-dependent */
	सचे (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		पटिनिवत्त -1;
	}
	सचे (pwc != रिक्त)
		*pwc = *s;
	पटिनिवत्त 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	पटिनिवत्त (j < 0 ? -j : j);
}
#endif

#ifndef HAVE_BZERO
शून्य
bzero(शून्य *b, size_t n)
{
	(शून्य)memset(b, 0, n);
}
#endif

#ifndef HAVE_RAISE
पूर्णाङ्क
उत्थापय(पूर्णाङ्क sig)
{
	पटिनिवत्त kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	पटिनिवत्त -1;
}
#endif

#ifndef HAVE_KILLPG
पूर्णाङ्क
killpg(pid_t pgrp, पूर्णाङ्क sig)
{
	पटिनिवत्त kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
पूर्णाङ्क _ssh_compat_fflush(FILE *f)
{
	पूर्णाङ्क r1, r2;

	सचे (f == रिक्त) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		सचे (r1 == -1 || r2 == -1)
			पटिनिवत्त -1;
		पटिनिवत्त 0;
	}
	पटिनिवत्त fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
संरचना tm *
localtime_r(ध्रुव time_t *timep, संरचना tm *result)
{
	संरचना tm *tm = localtime(timep);
	*result = *tm;
	पटिनिवत्त result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
पूर्णाङ्क
clock_gettime(clockid_t clockid, संरचना timespec *ts)
{
	संरचना timeval tv;

	सचे (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		पटिनिवत्त -1;
	}
	सचे (ts == रिक्त) {
		errno = EFAULT;
		पटिनिवत्त -1;
	}

	सचे (gettimeofday(&tv, रिक्त) == -1)
		पटिनिवत्त -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	पटिनिवत्त 0;
}
#endif

#ifdef ASAN_OPTIONS
ध्रुव वर्ण *__asan_default_options(शून्य) {
	पटिनिवत्त ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
ध्रुव वर्ण *__msan_default_options(शून्य) {
	पटिनिवत्त MSAN_OPTIONS;
}
#endif
