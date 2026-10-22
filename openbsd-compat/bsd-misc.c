
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
अक्षर *__progname;
#endif

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
अक्षर *ssh_get_progname(अक्षर *argv0)
{
	अक्षर *p, *q;
#ifdef HAVE___PROGNAME
	बाह्य अक्षर *__progname;

	p = __progname;
#अन्यथा
	जर (argv0 == रिक्त)
		परत ("unknown");	/* XXX */
	p = म_खोजप(argv0, '/');
	जर (p == रिक्त)
		p = argv0;
	अन्यथा
		p++;
#endif
	जर ((q = strdup(p)) == रिक्त) {
		लिखो_त्रुटि("strdup");
		निकास(1);
	}
	परत q;
}

#ifndef HAVE_SETLOGIN
पूर्णांक setlogin(स्थिरांक अक्षर *name)
{
	परत (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
पूर्णांक innetgr(स्थिरांक अक्षर *netgroup, स्थिरांक अक्षर *host,
	    स्थिरांक अक्षर *user, स्थिरांक अक्षर *domain)
{
	परत (0);
}
#endif /* HAVE_INNETGR */

#जर !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
पूर्णांक seteuid(uid_t euid)
{
	परत (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#जर !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
पूर्णांक setegid(uid_t egid)
{
	परत(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#जर !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
स्थिरांक अक्षर *म_त्रुटि(पूर्णांक e)
{
	बाह्य पूर्णांक sys_nerr;
	बाह्य अक्षर *sys_errlist[];

	जर ((e >= 0) && (e < sys_nerr))
		परत (sys_errlist[e]);

	परत ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
पूर्णांक utimes(स्थिरांक अक्षर *filename, संरचना timeval *tvp)
{
	संरचना utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	परत (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
पूर्णांक
utimensat(पूर्णांक fd, स्थिरांक अक्षर *path, स्थिरांक संरचना timespec बार[2],
    पूर्णांक flag)
{
	संरचना timeval tv[2];
# ifdef HAVE_FUTIMES
	पूर्णांक ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = बार[0].tv_sec;
	tv[0].tv_usec = बार[0].tv_nsec / 1000;
	tv[1].tv_sec = बार[1].tv_sec;
	tv[1].tv_usec = बार[1].tv_nsec / 1000;

	जर (fd != AT_FDCWD) {
		त्रुटि_सं = ENOSYS;
		परत -1;
	}
# ifndef HAVE_FUTIMES
	परत utimes(path, tv);
# अन्यथा
#  ifdef O_NOFOLLOW
	जर (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	जर ((fd = खोलो(path, oflags)) == -1)
		परत -1;
	ret = futimes(fd, tv);
	बंद(fd);
	परत ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
पूर्णांक
dirfd(शून्य *dir)
{
	त्रुटि_सं = ENOSYS;
	परत -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
पूर्णांक
fchownat(पूर्णांक fd, स्थिरांक अक्षर *path, uid_t owner, gid_t group, पूर्णांक flag)
{
	पूर्णांक ret, oflags = O_WRONLY;

	जर (fd != AT_FDCWD) {
		त्रुटि_सं = ENOSYS;
		परत -1;
	}
# ifndef HAVE_FCHOWN
	परत chown(path, owner, group);
# अन्यथा
#  ifdef O_NOFOLLOW
	जर (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	जर ((fd = खोलो(path, oflags)) == -1)
		परत -1;
	ret = fchown(fd, owner, group);
	बंद(fd);
	परत ret;
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
पूर्णांक
fchmodat(पूर्णांक fd, स्थिरांक अक्षर *path, mode_t mode, पूर्णांक flag)
{
	पूर्णांक ret, oflags = O_WRONLY;

	जर (fd != AT_FDCWD) {
		त्रुटि_सं = ENOSYS;
		परत -1;
	}
# ifndef HAVE_FCHMOD
	परत chmod(path, mode);
# अन्यथा
#  ifdef O_NOFOLLOW
	जर (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	जर ((fd = खोलो(path, oflags)) == -1)
		परत -1;
	ret = fchmod(fd, mode);
	बंद(fd);
	परत ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
पूर्णांक
fstatat(पूर्णांक dirfd, स्थिरांक अक्षर *path, संरचना stat *sb, पूर्णांक flag)
{
	जर (dirfd != AT_FDCWD && path && path[0] != '/') {
		त्रुटि_सं = ENOSYS;
		परत -1;
	}
	जर (flag == 0)
		परत stat(path, sb);
	अन्यथा जर (flag == AT_SYMLINK_NOFOLLOW)
		परत lstat(path, sb);
	त्रुटि_सं = ENOSYS;
	परत -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
पूर्णांक
unlinkat(पूर्णांक dirfd, स्थिरांक अक्षर *path, पूर्णांक flag)
{
	जर (dirfd != AT_FDCWD && path && path[0] != '/') {
		त्रुटि_सं = ENOSYS;
		परत -1;
	}
	जर (flag == 0)
		परत unlink(path);
	त्रुटि_सं = ENOSYS;
	परत -1;
}
#endif

#ifndef HAVE_TRUNCATE
पूर्णांक truncate(स्थिरांक अक्षर *path, off_t length)
{
	पूर्णांक fd, ret, saverrno;

	fd = खोलो(path, O_WRONLY);
	जर (fd < 0)
		परत (-1);

	ret = ftruncate(fd, length);
	saverrno = त्रुटि_सं;
	बंद(fd);
	जर (ret == -1)
		त्रुटि_सं = saverrno;

	परत(ret);
}
#endif /* HAVE_TRUNCATE */

#जर !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
पूर्णांक nanosleep(स्थिरांक संरचना timespec *req, संरचना timespec *rem)
{
	पूर्णांक rc, saverrno;
	बाह्य पूर्णांक त्रुटि_सं;
	संरचना timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(शून्य) gettimeofday(&tstart, रिक्त);
	rc = select(0, रिक्त, रिक्त, रिक्त, &time2wait);
	जर (rc == -1) {
		saverrno = त्रुटि_सं;
		(शून्य) gettimeofday (&tstop, रिक्त);
		त्रुटि_सं = saverrno;
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
	जर (rem != रिक्त)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	परत(rc);
}
#endif

#जर !defined(HAVE_USLEEP)
पूर्णांक usleep(अचिन्हित पूर्णांक useconds)
{
	संरचना timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	परत nanosleep(&ts, रिक्त);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(पूर्णांक fd)
{
	पूर्णांक ctty_pgrp;

	जर (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		परत(-1);
	अन्यथा
		परत(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
पूर्णांक
tcsendbreak(पूर्णांक fd, पूर्णांक duration)
{
# जर defined(TIOCSBRK) && defined(TIOCCBRK)
	संरचना timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	जर (ioctl(fd, TIOCSBRK, 0) == -1)
		परत (-1);
	(शून्य)select(0, 0, 0, 0, &sleepytime);
	जर (ioctl(fd, TIOCCBRK, 0) == -1)
		परत (-1);
	परत (0);
# अन्यथा
	परत -1;
# endif
}
#endif /* HAVE_TCSENDBREAK */

#ifndef HAVE_STRDUP
अक्षर *
strdup(स्थिरांक अक्षर *str)
{
	माप_प्रकार len;
	अक्षर *cp;

	len = म_माप(str) + 1;
	cp = दो_स्मृति(len);
	जर (cp != रिक्त)
		परत(स_नकल(cp, str, len));
	परत रिक्त;
}
#endif

#ifndef HAVE_ISBLANK
पूर्णांक
isblank(पूर्णांक c)
{
	परत (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#जर defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	परत getpgrp(pid);
#किंवाजर defined(HAVE_GETPGRP)
	जर (pid == 0)
		परत getpgrp();
#endif

	त्रुटि_सं = ESRCH;
	परत -1;
}
#endif

#ifndef HAVE_PLEDGE
पूर्णांक
pledge(स्थिरांक अक्षर *promises, स्थिरांक अक्षर *execpromises)
{
	परत 0;
}
#endif

#ifndef HAVE_UNVEIL
पूर्णांक
unveil(स्थिरांक अक्षर *path, स्थिरांक अक्षर *permissions)
{
	परत 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
पूर्णांक
mbtowc(ब_अक्षर_प्रकार *pwc, स्थिरांक अक्षर *s, माप_प्रकार n)
{
	जर (s == रिक्त || *s == '\0')
		परत 0;	/* ASCII is not state-dependent */
	जर (*s < 0 || *s > 0x7f || n < 1) {
		त्रुटि_सं = EOPNOTSUPP;
		परत -1;
	}
	जर (pwc != रिक्त)
		*pwc = *s;
	परत 1;
}
#endif

#ifndef HAVE_LLABS
दीर्घ दीर्घ
llabs(दीर्घ दीर्घ j)
{
	परत (j < 0 ? -j : j);
}
#endif

#ifndef HAVE_BZERO
शून्य
bzero(शून्य *b, माप_प्रकार n)
{
	(शून्य)स_रखो(b, 0, n);
}
#endif

#ifndef HAVE_RAISE
पूर्णांक
उठवा(पूर्णांक sig)
{
	परत समाप्त(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	त्रुटि_सं = ENOSYS;
	परत -1;
}
#endif

#ifndef HAVE_KILLPG
पूर्णांक
killpg(pid_t pgrp, पूर्णांक sig)
{
	परत समाप्त(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef ख_साफ
पूर्णांक _ssh_compat_fflush(खाता *f)
{
	पूर्णांक r1, r2;

	जर (f == रिक्त) {
		r1 = ख_साफ(मानक_निकास);
		r2 = ख_साफ(मानक_त्रुटि);
		जर (r1 == -1 || r2 == -1)
			परत -1;
		परत 0;
	}
	परत ख_साफ(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
संरचना पंचांग *
localtime_r(स्थिरांक समय_प्रकार *timep, संरचना पंचांग *result)
{
	संरचना पंचांग *पंचांग = स_स्थानीय(timep);
	*result = *पंचांग;
	परत result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
पूर्णांक
clock_gettime(clockid_t clockid, संरचना timespec *ts)
{
	संरचना timeval tv;

	जर (clockid != CLOCK_REALTIME) {
		त्रुटि_सं = ENOSYS;
		परत -1;
	}
	जर (ts == रिक्त) {
		त्रुटि_सं = EFAULT;
		परत -1;
	}

	जर (gettimeofday(&tv, रिक्त) == -1)
		परत -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (दीर्घ)tv.tv_usec * 1000;
	परत 0;
}
#endif

#ifdef ASAN_OPTIONS
स्थिरांक अक्षर *__asan_default_options(शून्य) {
	परत ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
स्थिरांक अक्षर *__msan_default_options(शून्य) {
	परत MSAN_OPTIONS;
}
#endif
