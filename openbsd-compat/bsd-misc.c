
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
#यदि_परिभाषितम् HAVE_SYS_SELECT_H
# include <sys/select.h>
#यदि_अन्तः
#अन्तर्भाव <sys/time.h>

#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>

#यदि_अपरिभाषितम् HAVE___PROGNAME
वर्ण *__progname;
#यदि_अन्तः

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
वर्ण *ssh_get_progname(वर्ण *argv0)
{
	वर्ण *p, *q;
#यदि_परिभाषितम् HAVE___PROGNAME
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
#यदि_अन्तः
	यदि ((q = strdup(p)) == रिक्त) {
		perror("strdup");
		निर्गच्छ(1);
	}
	प्रत्यागम q;
}

#यदि_अपरिभाषितम् HAVE_SETLOGIN
पूर्णाङ्क setlogin(ध्रुव वर्ण *name)
{
	प्रत्यागम (0);
}
#यदि_अन्तः /* !HAVE_SETLOGIN */

#यदि_अपरिभाषितम् HAVE_INNETGR
पूर्णाङ्क innetgr(ध्रुव वर्ण *netgroup, ध्रुव वर्ण *host,
	    ध्रुव वर्ण *user, ध्रुव वर्ण *domain)
{
	प्रत्यागम (0);
}
#यदि_अन्तः /* HAVE_INNETGR */

#यदि !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
पूर्णाङ्क seteuid(uid_t euid)
{
	प्रत्यागम (setreuid(-1, euid));
}
#यदि_अन्तः /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#यदि !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
पूर्णाङ्क setegid(uid_t egid)
{
	प्रत्यागम(setresgid(-1, egid, -1));
}
#यदि_अन्तः /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#यदि !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ध्रुव वर्ण *strerror(पूर्णाङ्क e)
{
	बाह्य पूर्णाङ्क sys_nerr;
	बाह्य वर्ण *sys_errlist[];

	यदि ((e >= 0) && (e < sys_nerr))
		प्रत्यागम (sys_errlist[e]);

	प्रत्यागम ("unlisted error");
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_UTIMES
पूर्णाङ्क utimes(ध्रुव वर्ण *filename, संरचना timeval *tvp)
{
	संरचना utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	प्रत्यागम (utime(filename, &ub));
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
पूर्णाङ्क
utimensat(पूर्णाङ्क fd, ध्रुव वर्ण *मार्गः, ध्रुव संरचना timespec times[2],
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
	प्रत्यागम utimes(मार्गः, tv);
# अन्यथा
#  ifdef O_NOFOLLOW
	यदि (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	यदि ((fd = उद्घाटय(मार्गः, oflags)) == -1)
		प्रत्यागम -1;
	ret = futimes(fd, tv);
	close(fd);
	प्रत्यागम ret;
# endif
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_DIRFD
पूर्णाङ्क
dirfd(शून्य *dir)
{
	errno = ENOSYS;
	प्रत्यागम -1;
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
पूर्णाङ्क
fchownat(पूर्णाङ्क fd, ध्रुव वर्ण *मार्गः, uid_t owner, gid_t गणः, पूर्णाङ्क flag)
{
	पूर्णाङ्क ret, oflags = O_WRONLY;

	यदि (fd != AT_FDCWD) {
		errno = ENOSYS;
		प्रत्यागम -1;
	}
# ifndef HAVE_FCHOWN
	प्रत्यागम chown(मार्गः, owner, गणः);
# अन्यथा
#  ifdef O_NOFOLLOW
	यदि (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	यदि ((fd = उद्घाटय(मार्गः, oflags)) == -1)
		प्रत्यागम -1;
	ret = fchown(fd, owner, गणः);
	close(fd);
	प्रत्यागम ret;
# endif
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
पूर्णाङ्क
fchmodat(पूर्णाङ्क fd, ध्रुव वर्ण *मार्गः, बहुलकम्_t बहुलकम्, पूर्णाङ्क flag)
{
	पूर्णाङ्क ret, oflags = O_WRONLY;

	यदि (fd != AT_FDCWD) {
		errno = ENOSYS;
		प्रत्यागम -1;
	}
# ifndef HAVE_FCHMOD
	प्रत्यागम chmod(मार्गः, बहुलकम्);
# अन्यथा
#  ifdef O_NOFOLLOW
	यदि (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	यदि ((fd = उद्घाटय(मार्गः, oflags)) == -1)
		प्रत्यागम -1;
	ret = fchmod(fd, बहुलकम्);
	close(fd);
	प्रत्यागम ret;
# endif
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
पूर्णाङ्क
fstatat(पूर्णाङ्क dirfd, ध्रुव वर्ण *मार्गः, संरचना stat *sb, पूर्णाङ्क flag)
{
	यदि (dirfd != AT_FDCWD && मार्गः && मार्गः[0] != '/') {
		errno = ENOSYS;
		प्रत्यागम -1;
	}
	यदि (flag == 0)
		प्रत्यागम stat(मार्गः, sb);
	अन्यथा यदि (flag == AT_SYMLINK_NOFOLLOW)
		प्रत्यागम lstat(मार्गः, sb);
	errno = ENOSYS;
	प्रत्यागम -1;
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
पूर्णाङ्क
unlinkat(पूर्णाङ्क dirfd, ध्रुव वर्ण *मार्गः, पूर्णाङ्क flag)
{
	यदि (dirfd != AT_FDCWD && मार्गः && मार्गः[0] != '/') {
		errno = ENOSYS;
		प्रत्यागम -1;
	}
	यदि (flag == 0)
		प्रत्यागम unlink(मार्गः);
	errno = ENOSYS;
	प्रत्यागम -1;
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_TRUNCATE
पूर्णाङ्क truncate(ध्रुव वर्ण *मार्गः, off_t दीर्घता)
{
	पूर्णाङ्क fd, ret, saverrno;

	fd = उद्घाटय(मार्गः, O_WRONLY);
	यदि (fd < 0)
		प्रत्यागम (-1);

	ret = ftruncate(fd, दीर्घता);
	saverrno = errno;
	close(fd);
	यदि (ret == -1)
		errno = saverrno;

	प्रत्यागम(ret);
}
#यदि_अन्तः /* HAVE_TRUNCATE */

#यदि !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
पूर्णाङ्क nanosleep(ध्रुव संरचना timespec *req, संरचना timespec *rem)
{
	पूर्णाङ्क rc, saverrno;
	बाह्य पूर्णाङ्क errno;
	संरचना timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_गन्तव्यम्_TIMEVAL(&time2wait, req)
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
		TIMEVAL_गन्तव्यम्_TIMESPEC(&tremain, rem)

	प्रत्यागम(rc);
}
#यदि_अन्तः

#यदि !defined(HAVE_USLEEP)
पूर्णाङ्क usleep(अचिह्नित पूर्णाङ्क useconds)
{
	संरचना timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	प्रत्यागम nanosleep(&ts, रिक्त);
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_TCGETPGRP
pid_t
tcgetpgrp(पूर्णाङ्क fd)
{
	पूर्णाङ्क ctty_pgrp;

	यदि (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		प्रत्यागम(-1);
	अन्यथा
		प्रत्यागम(ctty_pgrp);
}
#यदि_अन्तः /* HAVE_TCGETPGRP */

#यदि_अपरिभाषितम् HAVE_TCSENDBREAK
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
#यदि_अन्तः /* HAVE_TCSENDBREAK */

#यदि_अपरिभाषितम् HAVE_STRDUP
वर्ण *
strdup(ध्रुव वर्ण *str)
{
	आकार_t len;
	वर्ण *cp;

	len = वाक्यदैर्घ्यम्(str) + 1;
	cp = स्मृतिं_देहि(len);
	यदि (cp != रिक्त)
		प्रत्यागम(स्मृतिं_प्रतिलिख(cp, str, len));
	प्रत्यागम रिक्त;
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_ISBLANK
पूर्णाङ्क
isblank(पूर्णाङ्क c)
{
	प्रत्यागम (c == ' ' || c == '\t');
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#यदि defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	प्रत्यागम getpgrp(pid);
#नोचेद्यदि defined(HAVE_GETPGRP)
	यदि (pid == 0)
		प्रत्यागम getpgrp();
#यदि_अन्तः

	errno = ESRCH;
	प्रत्यागम -1;
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_PLEDGE
पूर्णाङ्क
pledge(ध्रुव वर्ण *promises, ध्रुव वर्ण *execpromises)
{
	प्रत्यागम 0;
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_UNVEIL
पूर्णाङ्क
unveil(ध्रुव वर्ण *मार्गः, ध्रुव वर्ण *permissions)
{
	प्रत्यागम 0;
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
पूर्णाङ्क
mbtowc(wchar_t *pwc, ध्रुव वर्ण *s, आकार_t n)
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
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_LLABS
दीर्घ दीर्घ
llabs(दीर्घ दीर्घ j)
{
	प्रत्यागम (j < 0 ? -j : j);
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_BZERO
शून्य
bzero(शून्य *b, आकार_t n)
{
	(शून्य)स्मृतिं_पूरय(b, 0, n);
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_RAISE
पूर्णाङ्क
उत्थापय(पूर्णाङ्क sig)
{
	प्रत्यागम kill(getpid(), sig);
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	प्रत्यागम -1;
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_KILLPG
पूर्णाङ्क
killpg(pid_t pgrp, पूर्णाङ्क sig)
{
	प्रत्यागम kill(pgrp, sig);
}
#यदि_अन्तः

#यदि_परिभाषितम् FFLUSH_NULL_BUG
#अपरिभाषय fflush
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
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_LOCALTIME_R
संरचना tm *
localtime_r(ध्रुव time_t *timep, संरचना tm *परिणाम)
{
	संरचना tm *tm = localtime(timep);
	*परिणाम = *tm;
	प्रत्यागम परिणाम;
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_CLOCK_GETTIME
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
	ts->tv_nsec = (दीर्घ)tv.tv_usec * 1000;
	प्रत्यागम 0;
}
#यदि_अन्तः

#यदि_परिभाषितम् ASAN_OPTIONS
ध्रुव वर्ण *__asan_default_options(शून्य) {
	प्रत्यागम ASAN_OPTIONS;
}
#यदि_अन्तः

#यदि_परिभाषितम् MSAN_OPTIONS
ध्रुव वर्ण *__msan_default_options(शून्य) {
	प्रत्यागम MSAN_OPTIONS;
}
#यदि_अन्तः
