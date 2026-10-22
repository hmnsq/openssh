
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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/ioctl.h>
#अगर_घोषित HAVE_SYS_SELECT_H
# include <sys/select.h>
#पूर्ण_अगर
#समावेश <sys/time.h>

#समावेश <fcntl.h>
#समावेश <string.h>
#समावेश <signal.h>
#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <time.h>
#समावेश <unistd.h>

#अगर_अघोषित HAVE___PROGNAME
अक्षर *__progname;
#पूर्ण_अगर

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
अक्षर *ssh_get_progname(अक्षर *argv0)
{
	अक्षर *p, *q;
#अगर_घोषित HAVE___PROGNAME
	बाह्य अक्षर *__progname;

	p = __progname;
#अन्यथा
	अगर (argv0 == शून्य)
		वापस ("unknown");	/* XXX */
	p = म_खोजप(argv0, '/');
	अगर (p == शून्य)
		p = argv0;
	अन्यथा
		p++;
#पूर्ण_अगर
	अगर ((q = strdup(p)) == शून्य) {
		लिखो_त्रुटि("strdup");
		निकास(1);
	}
	वापस q;
}

#अगर_अघोषित HAVE_SETLOGIN
पूर्णांक setlogin(स्थिर अक्षर *name)
{
	वापस (0);
}
#पूर्ण_अगर /* !HAVE_SETLOGIN */

#अगर_अघोषित HAVE_INNETGR
पूर्णांक innetgr(स्थिर अक्षर *netgroup, स्थिर अक्षर *host,
	    स्थिर अक्षर *user, स्थिर अक्षर *domain)
{
	वापस (0);
}
#पूर्ण_अगर /* HAVE_INNETGR */

#अगर !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
पूर्णांक seteuid(uid_t euid)
{
	वापस (setreuid(-1, euid));
}
#पूर्ण_अगर /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#अगर !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
पूर्णांक setegid(uid_t egid)
{
	वापस(setresgid(-1, egid, -1));
}
#पूर्ण_अगर /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#अगर !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
स्थिर अक्षर *म_त्रुटि(पूर्णांक e)
{
	बाह्य पूर्णांक sys_nerr;
	बाह्य अक्षर *sys_errlist[];

	अगर ((e >= 0) && (e < sys_nerr))
		वापस (sys_errlist[e]);

	वापस ("unlisted error");
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_UTIMES
पूर्णांक utimes(स्थिर अक्षर *filename, काष्ठा timeval *tvp)
{
	काष्ठा utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	वापस (utime(filename, &ub));
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
पूर्णांक
utimensat(पूर्णांक fd, स्थिर अक्षर *path, स्थिर काष्ठा timespec बार[2],
    पूर्णांक flag)
{
	काष्ठा timeval tv[2];
# ifdef HAVE_FUTIMES
	पूर्णांक ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = बार[0].tv_sec;
	tv[0].tv_usec = बार[0].tv_nsec / 1000;
	tv[1].tv_sec = बार[1].tv_sec;
	tv[1].tv_usec = बार[1].tv_nsec / 1000;

	अगर (fd != AT_FDCWD) {
		त्रुटि_सं = ENOSYS;
		वापस -1;
	}
# ifndef HAVE_FUTIMES
	वापस utimes(path, tv);
# अन्यथा
#  ifdef O_NOFOLLOW
	अगर (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	अगर ((fd = खोलो(path, oflags)) == -1)
		वापस -1;
	ret = futimes(fd, tv);
	बंद(fd);
	वापस ret;
# endif
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_DIRFD
पूर्णांक
dirfd(व्योम *dir)
{
	त्रुटि_सं = ENOSYS;
	वापस -1;
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
पूर्णांक
fchownat(पूर्णांक fd, स्थिर अक्षर *path, uid_t owner, gid_t group, पूर्णांक flag)
{
	पूर्णांक ret, oflags = O_WRONLY;

	अगर (fd != AT_FDCWD) {
		त्रुटि_सं = ENOSYS;
		वापस -1;
	}
# ifndef HAVE_FCHOWN
	वापस chown(path, owner, group);
# अन्यथा
#  ifdef O_NOFOLLOW
	अगर (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	अगर ((fd = खोलो(path, oflags)) == -1)
		वापस -1;
	ret = fchown(fd, owner, group);
	बंद(fd);
	वापस ret;
# endif
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
पूर्णांक
fchmodat(पूर्णांक fd, स्थिर अक्षर *path, mode_t mode, पूर्णांक flag)
{
	पूर्णांक ret, oflags = O_WRONLY;

	अगर (fd != AT_FDCWD) {
		त्रुटि_सं = ENOSYS;
		वापस -1;
	}
# ifndef HAVE_FCHMOD
	वापस chmod(path, mode);
# अन्यथा
#  ifdef O_NOFOLLOW
	अगर (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	अगर ((fd = खोलो(path, oflags)) == -1)
		वापस -1;
	ret = fchmod(fd, mode);
	बंद(fd);
	वापस ret;
# endif
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
पूर्णांक
fstatat(पूर्णांक dirfd, स्थिर अक्षर *path, काष्ठा stat *sb, पूर्णांक flag)
{
	अगर (dirfd != AT_FDCWD && path && path[0] != '/') {
		त्रुटि_सं = ENOSYS;
		वापस -1;
	}
	अगर (flag == 0)
		वापस stat(path, sb);
	अन्यथा अगर (flag == AT_SYMLINK_NOFOLLOW)
		वापस lstat(path, sb);
	त्रुटि_सं = ENOSYS;
	वापस -1;
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
पूर्णांक
unlinkat(पूर्णांक dirfd, स्थिर अक्षर *path, पूर्णांक flag)
{
	अगर (dirfd != AT_FDCWD && path && path[0] != '/') {
		त्रुटि_सं = ENOSYS;
		वापस -1;
	}
	अगर (flag == 0)
		वापस unlink(path);
	त्रुटि_सं = ENOSYS;
	वापस -1;
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_TRUNCATE
पूर्णांक truncate(स्थिर अक्षर *path, off_t लंबाई)
{
	पूर्णांक fd, ret, saverrno;

	fd = खोलो(path, O_WRONLY);
	अगर (fd < 0)
		वापस (-1);

	ret = ftruncate(fd, लंबाई);
	saverrno = त्रुटि_सं;
	बंद(fd);
	अगर (ret == -1)
		त्रुटि_सं = saverrno;

	वापस(ret);
}
#पूर्ण_अगर /* HAVE_TRUNCATE */

#अगर !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
पूर्णांक nanosleep(स्थिर काष्ठा timespec *req, काष्ठा timespec *rem)
{
	पूर्णांक rc, saverrno;
	बाह्य पूर्णांक त्रुटि_सं;
	काष्ठा timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(व्योम) gettimeofday(&tstart, शून्य);
	rc = select(0, शून्य, शून्य, शून्य, &time2wait);
	अगर (rc == -1) {
		saverrno = त्रुटि_सं;
		(व्योम) gettimeofday (&tstop, शून्य);
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
	अगर (rem != शून्य)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	वापस(rc);
}
#पूर्ण_अगर

#अगर !defined(HAVE_USLEEP)
पूर्णांक usleep(अचिन्हित पूर्णांक useconds)
{
	काष्ठा timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	वापस nanosleep(&ts, शून्य);
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_TCGETPGRP
pid_t
tcgetpgrp(पूर्णांक fd)
{
	पूर्णांक ctty_pgrp;

	अगर (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		वापस(-1);
	अन्यथा
		वापस(ctty_pgrp);
}
#पूर्ण_अगर /* HAVE_TCGETPGRP */

#अगर_अघोषित HAVE_TCSENDBREAK
पूर्णांक
tcsendbreak(पूर्णांक fd, पूर्णांक duration)
{
# अगर defined(TIOCSBRK) && defined(TIOCCBRK)
	काष्ठा timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	अगर (ioctl(fd, TIOCSBRK, 0) == -1)
		वापस (-1);
	(व्योम)select(0, 0, 0, 0, &sleepytime);
	अगर (ioctl(fd, TIOCCBRK, 0) == -1)
		वापस (-1);
	वापस (0);
# अन्यथा
	वापस -1;
# endif
}
#पूर्ण_अगर /* HAVE_TCSENDBREAK */

#अगर_अघोषित HAVE_STRDUP
अक्षर *
strdup(स्थिर अक्षर *str)
{
	माप_प्रकार len;
	अक्षर *cp;

	len = म_माप(str) + 1;
	cp = दो_स्मृति(len);
	अगर (cp != शून्य)
		वापस(स_नकल(cp, str, len));
	वापस शून्य;
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_ISBLANK
पूर्णांक
isblank(पूर्णांक c)
{
	वापस (c == ' ' || c == '\t');
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#अगर defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	वापस getpgrp(pid);
#या_अगर defined(HAVE_GETPGRP)
	अगर (pid == 0)
		वापस getpgrp();
#पूर्ण_अगर

	त्रुटि_सं = ESRCH;
	वापस -1;
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_PLEDGE
पूर्णांक
pledge(स्थिर अक्षर *promises, स्थिर अक्षर *execpromises)
{
	वापस 0;
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_UNVEIL
पूर्णांक
unveil(स्थिर अक्षर *path, स्थिर अक्षर *permissions)
{
	वापस 0;
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
पूर्णांक
mbtowc(ब_अक्षर_प्रकार *pwc, स्थिर अक्षर *s, माप_प्रकार n)
{
	अगर (s == शून्य || *s == '\0')
		वापस 0;	/* ASCII is not state-dependent */
	अगर (*s < 0 || *s > 0x7f || n < 1) {
		त्रुटि_सं = EOPNOTSUPP;
		वापस -1;
	}
	अगर (pwc != शून्य)
		*pwc = *s;
	वापस 1;
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_LLABS
दीर्घ दीर्घ
llabs(दीर्घ दीर्घ j)
{
	वापस (j < 0 ? -j : j);
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_BZERO
व्योम
bzero(व्योम *b, माप_प्रकार n)
{
	(व्योम)स_रखो(b, 0, n);
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_RAISE
पूर्णांक
उठाओ(पूर्णांक sig)
{
	वापस समाप्त(getpid(), sig);
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	त्रुटि_सं = ENOSYS;
	वापस -1;
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_KILLPG
पूर्णांक
killpg(pid_t pgrp, पूर्णांक sig)
{
	वापस समाप्त(pgrp, sig);
}
#पूर्ण_अगर

#अगर_घोषित FFLUSH_NULL_BUG
#अघोषित ख_साफ
पूर्णांक _ssh_compat_fflush(खाता *f)
{
	पूर्णांक r1, r2;

	अगर (f == शून्य) {
		r1 = ख_साफ(मानक_निकास);
		r2 = ख_साफ(मानक_त्रुटि);
		अगर (r1 == -1 || r2 == -1)
			वापस -1;
		वापस 0;
	}
	वापस ख_साफ(f);
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_LOCALTIME_R
काष्ठा पंचांग *
localtime_r(स्थिर समय_प्रकार *timep, काष्ठा पंचांग *परिणाम)
{
	काष्ठा पंचांग *पंचांग = स_स्थानीय(timep);
	*परिणाम = *पंचांग;
	वापस परिणाम;
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_CLOCK_GETTIME
पूर्णांक
clock_gettime(clockid_t clockid, काष्ठा timespec *ts)
{
	काष्ठा timeval tv;

	अगर (clockid != CLOCK_REALTIME) {
		त्रुटि_सं = ENOSYS;
		वापस -1;
	}
	अगर (ts == शून्य) {
		त्रुटि_सं = EFAULT;
		वापस -1;
	}

	अगर (gettimeofday(&tv, शून्य) == -1)
		वापस -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (दीर्घ)tv.tv_usec * 1000;
	वापस 0;
}
#पूर्ण_अगर

#अगर_घोषित ASAN_OPTIONS
स्थिर अक्षर *__asan_default_options(व्योम) {
	वापस ASAN_OPTIONS;
}
#पूर्ण_अगर

#अगर_घोषित MSAN_OPTIONS
स्थिर अक्षर *__msan_default_options(व्योम) {
	वापस MSAN_OPTIONS;
}
#पूर्ण_अगर
