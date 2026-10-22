
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
		फर्काऊ ("unknown");	/* XXX */
	p = म_खोजप(argv0, '/');
	यदि (p == रिक्त)
		p = argv0;
	अन्यथा
		p++;
#endif
	यदि ((q = strdup(p)) == रिक्त) {
		लिखो_त्रुटि("strdup");
		निकास(1);
	}
	फर्काऊ q;
}

#ifndef HAVE_SETLOGIN
पूर्णाङ्क setlogin(अचर वर्ण *name)
{
	फर्काऊ (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
पूर्णाङ्क innetgr(अचर वर्ण *netgroup, अचर वर्ण *host,
	    अचर वर्ण *user, अचर वर्ण *domain)
{
	फर्काऊ (0);
}
#endif /* HAVE_INNETGR */

#यदि !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
पूर्णाङ्क seteuid(uid_t euid)
{
	फर्काऊ (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#यदि !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
पूर्णाङ्क setegid(uid_t egid)
{
	फर्काऊ(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#यदि !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
अचर वर्ण *म_त्रुटि(पूर्णाङ्क e)
{
	बाह्य पूर्णाङ्क sys_nerr;
	बाह्य वर्ण *sys_errlist[];

	यदि ((e >= 0) && (e < sys_nerr))
		फर्काऊ (sys_errlist[e]);

	फर्काऊ ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
पूर्णाङ्क utimes(अचर वर्ण *filename, संरचना timeval *tvp)
{
	संरचना utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	फर्काऊ (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
पूर्णाङ्क
utimensat(पूर्णाङ्क fd, अचर वर्ण *path, अचर संरचना timespec बार[2],
    पूर्णाङ्क flag)
{
	संरचना timeval tv[2];
# ifdef HAVE_FUTIMES
	पूर्णाङ्क ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = बार[0].tv_sec;
	tv[0].tv_usec = बार[0].tv_nsec / 1000;
	tv[1].tv_sec = बार[1].tv_sec;
	tv[1].tv_usec = बार[1].tv_nsec / 1000;

	यदि (fd != AT_FDCWD) {
		त्रुटि_सं = ENOSYS;
		फर्काऊ -1;
	}
# ifndef HAVE_FUTIMES
	फर्काऊ utimes(path, tv);
# अन्यथा
#  ifdef O_NOFOLLOW
	यदि (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	यदि ((fd = खोलो(path, oflags)) == -1)
		फर्काऊ -1;
	ret = futimes(fd, tv);
	बंद(fd);
	फर्काऊ ret;
# endif
}
#endif

#ifndef HAVE_DIRFD
पूर्णाङ्क
dirfd(शून्य *dir)
{
	त्रुटि_सं = ENOSYS;
	फर्काऊ -1;
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
पूर्णाङ्क
fchownat(पूर्णाङ्क fd, अचर वर्ण *path, uid_t owner, gid_t group, पूर्णाङ्क flag)
{
	पूर्णाङ्क ret, oflags = O_WRONLY;

	यदि (fd != AT_FDCWD) {
		त्रुटि_सं = ENOSYS;
		फर्काऊ -1;
	}
# ifndef HAVE_FCHOWN
	फर्काऊ chown(path, owner, group);
# अन्यथा
#  ifdef O_NOFOLLOW
	यदि (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	यदि ((fd = खोलो(path, oflags)) == -1)
		फर्काऊ -1;
	ret = fchown(fd, owner, group);
	बंद(fd);
	फर्काऊ ret;
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
fchmodat(पूर्णाङ्क fd, अचर वर्ण *path, mode_t mode, पूर्णाङ्क flag)
{
	पूर्णाङ्क ret, oflags = O_WRONLY;

	यदि (fd != AT_FDCWD) {
		त्रुटि_सं = ENOSYS;
		फर्काऊ -1;
	}
# ifndef HAVE_FCHMOD
	फर्काऊ chmod(path, mode);
# अन्यथा
#  ifdef O_NOFOLLOW
	यदि (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	यदि ((fd = खोलो(path, oflags)) == -1)
		फर्काऊ -1;
	ret = fchmod(fd, mode);
	बंद(fd);
	फर्काऊ ret;
# endif
}
#endif

#ifndef HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
पूर्णाङ्क
fstatat(पूर्णाङ्क dirfd, अचर वर्ण *path, संरचना stat *sb, पूर्णाङ्क flag)
{
	यदि (dirfd != AT_FDCWD && path && path[0] != '/') {
		त्रुटि_सं = ENOSYS;
		फर्काऊ -1;
	}
	यदि (flag == 0)
		फर्काऊ stat(path, sb);
	अन्यथा यदि (flag == AT_SYMLINK_NOFOLLOW)
		फर्काऊ lstat(path, sb);
	त्रुटि_सं = ENOSYS;
	फर्काऊ -1;
}
#endif

#ifndef HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
पूर्णाङ्क
unlinkat(पूर्णाङ्क dirfd, अचर वर्ण *path, पूर्णाङ्क flag)
{
	यदि (dirfd != AT_FDCWD && path && path[0] != '/') {
		त्रुटि_सं = ENOSYS;
		फर्काऊ -1;
	}
	यदि (flag == 0)
		फर्काऊ unlink(path);
	त्रुटि_सं = ENOSYS;
	फर्काऊ -1;
}
#endif

#ifndef HAVE_TRUNCATE
पूर्णाङ्क truncate(अचर वर्ण *path, off_t length)
{
	पूर्णाङ्क fd, ret, saverrno;

	fd = खोलो(path, O_WRONLY);
	यदि (fd < 0)
		फर्काऊ (-1);

	ret = ftruncate(fd, length);
	saverrno = त्रुटि_सं;
	बंद(fd);
	यदि (ret == -1)
		त्रुटि_सं = saverrno;

	फर्काऊ(ret);
}
#endif /* HAVE_TRUNCATE */

#यदि !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
पूर्णाङ्क nanosleep(अचर संरचना timespec *req, संरचना timespec *rem)
{
	पूर्णाङ्क rc, saverrno;
	बाह्य पूर्णाङ्क त्रुटि_सं;
	संरचना timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(शून्य) gettimeofday(&tstart, रिक्त);
	rc = select(0, रिक्त, रिक्त, रिक्त, &time2wait);
	यदि (rc == -1) {
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
	यदि (rem != रिक्त)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	फर्काऊ(rc);
}
#endif

#यदि !defined(HAVE_USLEEP)
पूर्णाङ्क usleep(अचिन्हित पूर्णाङ्क useconds)
{
	संरचना timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	फर्काऊ nanosleep(&ts, रिक्त);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(पूर्णाङ्क fd)
{
	पूर्णाङ्क ctty_pgrp;

	यदि (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		फर्काऊ(-1);
	अन्यथा
		फर्काऊ(ctty_pgrp);
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
		फर्काऊ (-1);
	(शून्य)select(0, 0, 0, 0, &sleepytime);
	यदि (ioctl(fd, TIOCCBRK, 0) == -1)
		फर्काऊ (-1);
	फर्काऊ (0);
# अन्यथा
	फर्काऊ -1;
# endif
}
#endif /* HAVE_TCSENDBREAK */

#ifndef HAVE_STRDUP
वर्ण *
strdup(अचर वर्ण *str)
{
	माप_प्रकार len;
	वर्ण *cp;

	len = म_माप(str) + 1;
	cp = दो_स्मृति(len);
	यदि (cp != रिक्त)
		फर्काऊ(स_नकल(cp, str, len));
	फर्काऊ रिक्त;
}
#endif

#ifndef HAVE_ISBLANK
पूर्णाङ्क
isblank(पूर्णाङ्क c)
{
	फर्काऊ (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#यदि defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	फर्काऊ getpgrp(pid);
#अथवायदि defined(HAVE_GETPGRP)
	यदि (pid == 0)
		फर्काऊ getpgrp();
#endif

	त्रुटि_सं = ESRCH;
	फर्काऊ -1;
}
#endif

#ifndef HAVE_PLEDGE
पूर्णाङ्क
pledge(अचर वर्ण *promises, अचर वर्ण *execpromises)
{
	फर्काऊ 0;
}
#endif

#ifndef HAVE_UNVEIL
पूर्णाङ्क
unveil(अचर वर्ण *path, अचर वर्ण *permissions)
{
	फर्काऊ 0;
}
#endif

#ifndef HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
पूर्णाङ्क
mbtowc(ब_अक्षर_प्रकार *pwc, अचर वर्ण *s, माप_प्रकार n)
{
	यदि (s == रिक्त || *s == '\0')
		फर्काऊ 0;	/* ASCII is not state-dependent */
	यदि (*s < 0 || *s > 0x7f || n < 1) {
		त्रुटि_सं = EOPNOTSUPP;
		फर्काऊ -1;
	}
	यदि (pwc != रिक्त)
		*pwc = *s;
	फर्काऊ 1;
}
#endif

#ifndef HAVE_LLABS
दीर्घ दीर्घ
llabs(दीर्घ दीर्घ j)
{
	फर्काऊ (j < 0 ? -j : j);
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
पूर्णाङ्क
उत्थापय(पूर्णाङ्क sig)
{
	फर्काऊ समाप्त(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	त्रुटि_सं = ENOSYS;
	फर्काऊ -1;
}
#endif

#ifndef HAVE_KILLPG
पूर्णाङ्क
killpg(pid_t pgrp, पूर्णाङ्क sig)
{
	फर्काऊ समाप्त(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef ख_साफ
पूर्णाङ्क _ssh_compat_fflush(खाता *f)
{
	पूर्णाङ्क r1, r2;

	यदि (f == रिक्त) {
		r1 = ख_साफ(मानक_निकास);
		r2 = ख_साफ(मानक_त्रुटि);
		यदि (r1 == -1 || r2 == -1)
			फर्काऊ -1;
		फर्काऊ 0;
	}
	फर्काऊ ख_साफ(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
संरचना पंचांग *
localtime_r(अचर समय_प्रकार *timep, संरचना पंचांग *result)
{
	संरचना पंचांग *पंचांग = स_स्थानीय(timep);
	*result = *पंचांग;
	फर्काऊ result;
}
#endif

#ifndef HAVE_CLOCK_GETTIME
पूर्णाङ्क
clock_gettime(clockid_t clockid, संरचना timespec *ts)
{
	संरचना timeval tv;

	यदि (clockid != CLOCK_REALTIME) {
		त्रुटि_सं = ENOSYS;
		फर्काऊ -1;
	}
	यदि (ts == रिक्त) {
		त्रुटि_सं = EFAULT;
		फर्काऊ -1;
	}

	यदि (gettimeofday(&tv, रिक्त) == -1)
		फर्काऊ -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (दीर्घ)tv.tv_usec * 1000;
	फर्काऊ 0;
}
#endif

#ifdef ASAN_OPTIONS
अचर वर्ण *__asan_default_options(शून्य) {
	फर्काऊ ASAN_OPTIONS;
}
#endif

#ifdef MSAN_OPTIONS
अचर वर्ण *__msan_default_options(शून्य) {
	फर्काऊ MSAN_OPTIONS;
}
#endif
