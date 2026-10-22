
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
#अन्यथा
	यदि (argv0 == रिक्त)
		प्रत्यागम ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	यदि (p == रिक्त)
		p = argv0;
	अन्यथा
		p++;
#endif
	यदि ((q = strdup(p)) == रिक्त) {
		perror("strdup");
		exit(1);
	}
	प्रत्यागम q;
}

#ifndef HAVE_SETLOGIN
पूर्णाङ्क setlogin(ध्रुव वर्ण *name)
{
	प्रत्यागम (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
पूर्णाङ्क innetgr(ध्रुव वर्ण *netgroup, ध्रुव वर्ण *host,
	    ध्रुव वर्ण *user, ध्रुव वर्ण *domain)
{
	प्रत्यागम (0);
}
#endif /* HAVE_INNETGR */

#यदि !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
पूर्णाङ्क seteuid(uid_t euid)
{
	प्रत्यागम (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#यदि !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
पूर्णाङ्क setegid(uid_t egid)
{
	प्रत्यागम(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#यदि !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ध्रुव वर्ण *strerror(पूर्णाङ्क e)
{
	बाह्य पूर्णाङ्क sys_nerr;
	बाह्य वर्ण *sys_errlist[];

	यदि ((e >= 0) && (e < sys_nerr))
		प्रत्यागम (sys_errlist[e]);

	प्रत्यागम ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
पूर्णाङ्क utimes(ध्रुव वर्ण *filename, संरचना timeval *tvp)
{
	संरचना utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	प्रत्यागम (utime(filename, &ub));
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

	यदि (fd != AT_FDCWD) {
		errno = ENOSYS;
		प्रत्यागम -1;
	}
# ifndef HAVE_FUTIMES
	प्रत्यागम utimes(path, tv);
# अन्यथा
#  ifdef O_NOFOLLOW
	यदि (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	यदि ((fd = open(path, oflags)) == -1)
		प्रत्यागम -1;
	ret = futimes(fd, tv);
	close(fd);
	प्रत्यागम ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
पूर्णाङ्क
dirfd(शून्य *dir)
{
	errno = ENOSYS;
	प्रत्यागम -1;
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

	यदि (fd != AT_FDCWD) {
		errno = ENOSYS;
		प्रत्यागम -1;
	}
# ifndef HAVE_FCHOWN
	प्रत्यागम chown(path, owner, group);
# अन्यथा
#  ifdef O_NOFOLLOW
	यदि (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	यदि ((fd = open(path, oflags)) == -1)
		प्रत्यागम -1;
	ret = fchown(fd, owner, group);
	close(fd);
	प्रत्यागम ret;
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

	यदि (fd != AT_FDCWD) {
		errno = ENOSYS;
		प्रत्यागम -1;
	}
# ifndef HAVE_FCHMOD
	प्रत्यागम chmod(path, mode);
# अन्यथा
#  ifdef O_NOFOLLOW
	यदि (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	यदि ((fd = open(path, oflags)) == -1)
		प्रत्यागम -1;
	ret = fchmod(fd, mode);
	close(fd);
	प्रत्यागम ret;
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
	यदि (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		प्रत्यागम -1;
	}
	यदि (flag == 0)
		प्रत्यागम stat(path, sb);
	अन्यथा यदि (flag == AT_SYMLINK_NOFOLLOW)
		प्रत्यागम lstat(path, sb);
	errno = ENOSYS;
	प्रत्यागम -1;
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
	यदि (dirfd != AT_FDCWD && path && path[0] != '/') {
		errno = ENOSYS;
		प्रत्यागम -1;
	}
	यदि (flag == 0)
		प्रत्यागम unlink(path);
	errno = ENOSYS;
	प्रत्यागम -1;
}
#endif

#ifndef HAVE_TRUNCATE
पूर्णाङ्क truncate(ध्रुव वर्ण *path, off_t length)
{
	पूर्णाङ्क fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	यदि (fd < 0)
		प्रत्यागम (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	यदि (ret == -1)
		errno = saverrno;

	प्रत्यागम(ret);
}
#endif /* HAVE_TRUNCATE */

#यदि !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
पूर्णाङ्क nanosleep(ध्रुव संरचना timespec *req, संरचना timespec *rem)
{
	पूर्णाङ्क rc, saverrno;
	बाह्य पूर्णाङ्क errno;
	संरचना timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(शून्य) gettimeofday(&tstart, रिक्त);
	rc = select(0, रिक्त, रिक्त, रिक्त, &time2wait);
	यदि (rc == -1) {
		saverrno = errno;
		(शून्य) gettimeofday (&tstop, रिक्त);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} अन्यथा {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	यदि (rem != रिक्त)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	प्रत्यागम(rc);
}
#endif

#यदि !defined(HAVE_USLEEP)
पूर्णाङ्क usleep(unsigned पूर्णाङ्क useconds)
{
	संरचना timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	प्रत्यागम nanosleep(&ts, रिक्त);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(पूर्णाङ्क fd)
{
	पूर्णाङ्क ctty_pgrp;

	यदि (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		प्रत्यागम(-1);
	अन्यथा
		प्रत्यागम(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
पूर्णाङ्क
tcsendbreak(पूर्णाङ्क fd, पूर्णाङ्क duration)
{
# यदि defined(TIOCSBRK) && defined(TIOCCBRK)
	संरचना timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	यदि (ioctl(fd, TIOCSBRK, 0) == -1)
		प्रत्यागम (-1);
	(शून्य)select(0, 0, 0, 0, &sleepytime);
	यदि (ioctl(fd, TIOCCBRK, 0) == -1)
		प्रत्यागम (-1);
	प्रत्यागम (0);
# अन्यथा
	प्रत्यागम -1;
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
	यदि (cp != रिक्त)
		प्रत्यागम(memcpy(cp, str, len));
	प्रत्यागम रिक्त;
}
#endif

#ifndef HAVE_ISBLANK
पूर्णाङ्क
isblank(पूर्णाङ्क c)
{
	प्रत्यागम (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#यदि defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	प्रत्यागम getpgrp(pid);
#नोचेद्यदि defined(HAVE_GETPGRP)
	यदि (pid == 0)
		प्रत्यागम getpgrp();
#endif

	errno = ESRCH;
	प्रत्यागम -1;
}
#endif

#ifndef HAVE_PLEDGE
पूर्णाङ्क
pledge(ध्रुव वर्ण *promises, ध्रुव वर्ण *execpromises)
{
	प्रत्यागम 0;
}
#endif

#ifndef HAVE_UNVEIL
पूर्णाङ्क
unveil(ध्रुव वर्ण *path, ध्रुव वर्ण *permissions)
{
	प्रत्यागम 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
पूर्णाङ्क
mbtowc(wchar_t *pwc, ध्रुव वर्ण *s, size_t n)
{
	यदि (s == रिक्त || *s == '\0')
		प्रत्यागम 0;	/* ASCII is not state-dependent */
	यदि (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		प्रत्यागम -1;
	}
	यदि (pwc != रिक्त)
		*pwc = *s;
	प्रत्यागम 1;
}
#endif

#ifndef HAVE_LLABS
long long
llabs(long long j)
{
	प्रत्यागम (j < 0 ? -j : j);
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
	प्रत्यागम kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	प्रत्यागम -1;
}
#endif

#ifndef HAVE_KILLPG
पूर्णाङ्क
killpg(pid_t pgrp, पूर्णाङ्क sig)
{
	प्रत्यागम kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
पूर्णाङ्क _ssh_compat_fflush(FILE *f)
{
	पूर्णाङ्क r1, r2;

	यदि (f == रिक्त) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		यदि (r1 == -1 || r2 == -1)
			प्रत्यागम -1;
		प्रत्यागम 0;
	}
	प्रत्यागम fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
संरचना tm *
localtime_r(ध्रुव time_t *timep, संरचना tm *result)
{
	संरचना tm *tm = localtime(timep);
	*result = *tm;
	प्रत्यागम result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
पूर्णाङ्क
clock_gettime(clockid_t clockid, संरचना timespec *ts)
{
	संरचना timeval tv;

	यदि (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		प्रत्यागम -1;
	}
	यदि (ts == रिक्त) {
		errno = EFAULT;
		प्रत्यागम -1;
	}

	यदि (gettimeofday(&tv, रिक्त) == -1)
		प्रत्यागम -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
	प्रत्यागम 0;
}
#endif

#ifdef ASAN_OPTIONS
ध्रुव वर्ण *__asan_default_options(शून्य) {
	प्रत्यागम ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
ध्रुव वर्ण *__msan_default_options(शून्य) {
	प्रत्यागम MSAN_OPTIONS;
}
#endif
