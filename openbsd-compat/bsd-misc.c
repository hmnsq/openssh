
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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/ioctl.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_SELECT_H
# include <sys/select.h>
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ <sys/time.h>

#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE___PROGNAME
ಅಕ್ಷರ *__progname;
#ಆದರೆ_ಅಂತ್ಯ

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
ಅಕ್ಷರ *ssh_get_progname(ಅಕ್ಷರ *argv0)
{
	ಅಕ್ಷರ *p, *q;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE___PROGNAME
	ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

	p = __progname;
#ಇಲ್ಲದಿದ್ದರೆ
	ಆದರೆ (argv0 == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	ಆದರೆ (p == ಖಾಲಿ)
		p = argv0;
	ಇಲ್ಲದಿದ್ದರೆ
		p++;
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ ((q = strdup(p)) == ಖಾಲಿ) {
		perror("strdup");
		ನಿರ್ಗಮಿಸು(1);
	}
	ಹಿಂತಿರುಗಿ q;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SETLOGIN
ಪೂರ್ಣಾಂಕ setlogin(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಹಿಂತಿರುಗಿ (0);
}
#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_SETLOGIN */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_INNETGR
ಪೂರ್ಣಾಂಕ innetgr(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *netgroup, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *domain)
{
	ಹಿಂತಿರುಗಿ (0);
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_INNETGR */

#ಆದರೆ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
ಪೂರ್ಣಾಂಕ seteuid(uid_t euid)
{
	ಹಿಂತಿರುಗಿ (setreuid(-1, euid));
}
#ಆದರೆ_ಅಂತ್ಯ /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ಆದರೆ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
ಪೂರ್ಣಾಂಕ setegid(uid_t egid)
{
	ಹಿಂತಿರುಗಿ(setresgid(-1, egid, -1));
}
#ಆದರೆ_ಅಂತ್ಯ /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ಆದರೆ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *strerror(ಪೂರ್ಣಾಂಕ e)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ sys_nerr;
	ಬಾಹ್ಯ ಅಕ್ಷರ *sys_errlist[];

	ಆದರೆ ((e >= 0) && (e < sys_nerr))
		ಹಿಂತಿರುಗಿ (sys_errlist[e]);

	ಹಿಂತಿರುಗಿ ("unlisted error");
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_UTIMES
ಪೂರ್ಣಾಂಕ utimes(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ರಚನೆ timeval *tvp)
{
	ರಚನೆ utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	ಹಿಂತಿರುಗಿ (utime(filename, &ub));
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ಪೂರ್ಣಾಂಕ
utimensat(ಪೂರ್ಣಾಂಕ fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ರಚನೆ timespec times[2],
    ಪೂರ್ಣಾಂಕ flag)
{
	ರಚನೆ timeval tv[2];
# ifdef HAVE_FUTIMES
	ಪೂರ್ಣಾಂಕ ret, oflags = O_WRONLY;
# endif

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

	ಆದರೆ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ಹಿಂತಿರುಗಿ -1;
	}
# ifndef HAVE_FUTIMES
	ಹಿಂತಿರುಗಿ utimes(ಮಾರ್ಗ, tv);
# ಇಲ್ಲದಿದ್ದರೆ
#  ifdef O_NOFOLLOW
	ಆದರೆ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ಆದರೆ ((fd = open(ಮಾರ್ಗ, oflags)) == -1)
		ಹಿಂತಿರುಗಿ -1;
	ret = futimes(fd, tv);
	close(fd);
	ಹಿಂತಿರುಗಿ ret;
# endif
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_DIRFD
ಪೂರ್ಣಾಂಕ
dirfd(ಶೂನ್ಯ *dir)
{
	errno = ENOSYS;
	ಹಿಂತಿರುಗಿ -1;
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ಪೂರ್ಣಾಂಕ
fchownat(ಪೂರ್ಣಾಂಕ fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, uid_t owner, gid_t ಗುಂಪು, ಪೂರ್ಣಾಂಕ flag)
{
	ಪೂರ್ಣಾಂಕ ret, oflags = O_WRONLY;

	ಆದರೆ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ಹಿಂತಿರುಗಿ -1;
	}
# ifndef HAVE_FCHOWN
	ಹಿಂತಿರುಗಿ chown(ಮಾರ್ಗ, owner, ಗುಂಪು);
# ಇಲ್ಲದಿದ್ದರೆ
#  ifdef O_NOFOLLOW
	ಆದರೆ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ಆದರೆ ((fd = open(ಮಾರ್ಗ, oflags)) == -1)
		ಹಿಂತಿರುಗಿ -1;
	ret = fchown(fd, owner, ಗುಂಪು);
	close(fd);
	ಹಿಂತಿರುಗಿ ret;
# endif
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by OpenSSH, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
ಪೂರ್ಣಾಂಕ
fchmodat(ಪೂರ್ಣಾಂಕ fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಬಹುಲಕ_t ಬಹುಲಕ, ಪೂರ್ಣಾಂಕ flag)
{
	ಪೂರ್ಣಾಂಕ ret, oflags = O_WRONLY;

	ಆದರೆ (fd != AT_FDCWD) {
		errno = ENOSYS;
		ಹಿಂತಿರುಗಿ -1;
	}
# ifndef HAVE_FCHMOD
	ಹಿಂತಿರುಗಿ chmod(ಮಾರ್ಗ, ಬಹುಲಕ);
# ಇಲ್ಲದಿದ್ದರೆ
#  ifdef O_NOFOLLOW
	ಆದರೆ (flag & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	ಆದರೆ ((fd = open(ಮಾರ್ಗ, oflags)) == -1)
		ಹಿಂತಿರುಗಿ -1;
	ret = fchmod(fd, ಬಹುಲಕ);
	close(fd);
	ಹಿಂತಿರುಗಿ ret;
# endif
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FSTATAT
/*
 * A limited implementation of fstatat that just has what OpenSSH uses:
 * cwd-relative and absolute paths, with or without following symlinks.
 */
ಪೂರ್ಣಾಂಕ
fstatat(ಪೂರ್ಣಾಂಕ dirfd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ರಚನೆ stat *sb, ಪೂರ್ಣಾಂಕ flag)
{
	ಆದರೆ (dirfd != AT_FDCWD && ಮಾರ್ಗ && ಮಾರ್ಗ[0] != '/') {
		errno = ENOSYS;
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (flag == 0)
		ಹಿಂತಿರುಗಿ stat(ಮಾರ್ಗ, sb);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (flag == AT_SYMLINK_NOFOLLOW)
		ಹಿಂತಿರುಗಿ lstat(ಮಾರ್ಗ, sb);
	errno = ENOSYS;
	ಹಿಂತಿರುಗಿ -1;
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_UNLINKAT
/*
 * A limited implementation of unlinkat that just has what OpenSSH uses:
 * cwd-relative and absolute paths.
 */
ಪೂರ್ಣಾಂಕ
unlinkat(ಪೂರ್ಣಾಂಕ dirfd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ flag)
{
	ಆದರೆ (dirfd != AT_FDCWD && ಮಾರ್ಗ && ಮಾರ್ಗ[0] != '/') {
		errno = ENOSYS;
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (flag == 0)
		ಹಿಂತಿರುಗಿ unlink(ಮಾರ್ಗ);
	errno = ENOSYS;
	ಹಿಂತಿರುಗಿ -1;
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_TRUNCATE
ಪೂರ್ಣಾಂಕ truncate(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, off_t ಉದ್ದಳತೆ)
{
	ಪೂರ್ಣಾಂಕ fd, ret, saverrno;

	fd = open(ಮಾರ್ಗ, O_WRONLY);
	ಆದರೆ (fd < 0)
		ಹಿಂತಿರುಗಿ (-1);

	ret = ftruncate(fd, ಉದ್ದಳತೆ);
	saverrno = errno;
	close(fd);
	ಆದರೆ (ret == -1)
		errno = saverrno;

	ಹಿಂತಿರುಗಿ(ret);
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_TRUNCATE */

#ಆದರೆ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
ಪೂರ್ಣಾಂಕ nanosleep(ಸ್ಥಿರಾಂಕ ರಚನೆ timespec *req, ರಚನೆ timespec *rem)
{
	ಪೂರ್ಣಾಂಕ rc, saverrno;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ errno;
	ರಚನೆ timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_ಗಮ್ಯ_TIMEVAL(&time2wait, req)
	(ಶೂನ್ಯ) gettimeofday(&tstart, ಖಾಲಿ);
	rc = select(0, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, &time2wait);
	ಆದರೆ (rc == -1) {
		saverrno = errno;
		(ಶೂನ್ಯ) gettimeofday (&tstop, ಖಾಲಿ);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} ಇಲ್ಲದಿದ್ದರೆ {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	ಆದರೆ (rem != ಖಾಲಿ)
		TIMEVAL_ಗಮ್ಯ_TIMESPEC(&tremain, rem)

	ಹಿಂತಿರುಗಿ(rc);
}
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(HAVE_USLEEP)
ಪೂರ್ಣಾಂಕ usleep(ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ useconds)
{
	ರಚನೆ timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	ಹಿಂತಿರುಗಿ nanosleep(&ts, ಖಾಲಿ);
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_TCGETPGRP
pid_t
tcgetpgrp(ಪೂರ್ಣಾಂಕ fd)
{
	ಪೂರ್ಣಾಂಕ ctty_pgrp;

	ಆದರೆ (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		ಹಿಂತಿರುಗಿ(-1);
	ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ(ctty_pgrp);
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_TCGETPGRP */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_TCSENDBREAK
ಪೂರ್ಣಾಂಕ
tcsendbreak(ಪೂರ್ಣಾಂಕ fd, ಪೂರ್ಣಾಂಕ duration)
{
# ಆದರೆ defined(TIOCSBRK) && defined(TIOCCBRK)
	ರಚನೆ timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	ಆದರೆ (ioctl(fd, TIOCSBRK, 0) == -1)
		ಹಿಂತಿರುಗಿ (-1);
	(ಶೂನ್ಯ)select(0, 0, 0, 0, &sleepytime);
	ಆದರೆ (ioctl(fd, TIOCCBRK, 0) == -1)
		ಹಿಂತಿರುಗಿ (-1);
	ಹಿಂತಿರುಗಿ (0);
# ಇಲ್ಲದಿದ್ದರೆ
	ಹಿಂತಿರುಗಿ -1;
# endif
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_TCSENDBREAK */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRDUP
ಅಕ್ಷರ *
strdup(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str)
{
	ಗಾತ್ರ_t len;
	ಅಕ್ಷರ *cp;

	len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(str) + 1;
	cp = ಸ್ಮರಣೆ_ಕೊಡು(len);
	ಆದರೆ (cp != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ(ಸ್ಮರಣೆ_ನಕಲು(cp, str, len));
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ISBLANK
ಪೂರ್ಣಾಂಕ
isblank(ಪೂರ್ಣಾಂಕ c)
{
	ಹಿಂತಿರುಗಿ (c == ' ' || c == '\t');
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#ಆದರೆ defined(HAVE_GETPGRP) && !defined(GETPGRP_VOID) && GETPGRP_VOID == 0
	ಹಿಂತಿರುಗಿ getpgrp(pid);
#ಅಥವಾಆದರೆ defined(HAVE_GETPGRP)
	ಆದರೆ (pid == 0)
		ಹಿಂತಿರುಗಿ getpgrp();
#ಆದರೆ_ಅಂತ್ಯ

	errno = ESRCH;
	ಹಿಂತಿರುಗಿ -1;
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_PLEDGE
ಪೂರ್ಣಾಂಕ
pledge(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *promises, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *execpromises)
{
	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_UNVEIL
ಪೂರ್ಣಾಂಕ
unveil(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *permissions)
{
	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_MBTOWC
/* a mbtowc that only supports ASCII */
ಪೂರ್ಣಾಂಕ
mbtowc(wchar_t *pwc, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ಗಾತ್ರ_t n)
{
	ಆದರೆ (s == ಖಾಲಿ || *s == '\0')
		ಹಿಂತಿರುಗಿ 0;	/* ASCII is not state-dependent */
	ಆದರೆ (*s < 0 || *s > 0x7f || n < 1) {
		errno = EOPNOTSUPP;
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (pwc != ಖಾಲಿ)
		*pwc = *s;
	ಹಿಂತಿರುಗಿ 1;
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_LLABS
ದೀರ್ಘ ದೀರ್ಘ
llabs(ದೀರ್ಘ ದೀರ್ಘ j)
{
	ಹಿಂತಿರುಗಿ (j < 0 ? -j : j);
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_BZERO
ಶೂನ್ಯ
bzero(ಶೂನ್ಯ *b, ಗಾತ್ರ_t n)
{
	(ಶೂನ್ಯ)memset(b, 0, n);
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_RAISE
ಪೂರ್ಣಾಂಕ
ಎತ್ತು(ಪೂರ್ಣಾಂಕ sig)
{
	ಹಿಂತಿರುಗಿ kill(getpid(), sig);
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	ಹಿಂತಿರುಗಿ -1;
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_KILLPG
ಪೂರ್ಣಾಂಕ
killpg(pid_t pgrp, ಪೂರ್ಣಾಂಕ sig)
{
	ಹಿಂತಿರುಗಿ kill(pgrp, sig);
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ FFLUSH_NULL_BUG
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು fflush
ಪೂರ್ಣಾಂಕ _ssh_compat_fflush(FILE *f)
{
	ಪೂರ್ಣಾಂಕ r1, r2;

	ಆದರೆ (f == ಖಾಲಿ) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		ಆದರೆ (r1 == -1 || r2 == -1)
			ಹಿಂತಿರುಗಿ -1;
		ಹಿಂತಿರುಗಿ 0;
	}
	ಹಿಂತಿರುಗಿ fflush(f);
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_LOCALTIME_R
ರಚನೆ tm *
localtime_r(ಸ್ಥಿರಾಂಕ time_t *timep, ರಚನೆ tm *ಫಲಿತಾಂಶ)
{
	ರಚನೆ tm *tm = localtime(timep);
	*ಫಲಿತಾಂಶ = *tm;
	ಹಿಂತಿರುಗಿ ಫಲಿತಾಂಶ;
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_CLOCK_GETTIME
ಪೂರ್ಣಾಂಕ
clock_gettime(clockid_t clockid, ರಚನೆ timespec *ts)
{
	ರಚನೆ timeval tv;

	ಆದರೆ (clockid != CLOCK_REALTIME) {
		errno = ENOSYS;
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (ts == ಖಾಲಿ) {
		errno = EFAULT;
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ (gettimeofday(&tv, ಖಾಲಿ) == -1)
		ಹಿಂತಿರುಗಿ -1;

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (ದೀರ್ಘ)tv.tv_usec * 1000;
	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ASAN_OPTIONS
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *__asan_default_options(ಶೂನ್ಯ) {
	ಹಿಂತಿರುಗಿ ASAN_OPTIONS;
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ MSAN_OPTIONS
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *__msan_default_options(ಶೂನ್ಯ) {
	ಹಿಂತಿರುಗಿ MSAN_OPTIONS;
}
#ಆದರೆ_ಅಂತ್ಯ
