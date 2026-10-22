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

#నిర్వచితం_కాకపోతే _BSD_MISC_H
#నిర్వచించు _BSD_MISC_H

#అన్తర్భావ "includes.h"

అక్షరం *ssh_get_progname(అక్షరం *);
పూర్ణాంకం విత్తనం_from_prngd(గుర్తులేని అక్షరం *, కొలత_t);

#నిర్వచితం_కాకపోతే HAVE_SETSID
#నిర్వచించు setsid() setpgrp(0, getpid())
#అయితే_ముగింపు /* !HAVE_SETSID */

#నిర్వచితం_కాకపోతే HAVE_SETENV
పూర్ణాంకం setenv(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం);
#అయితే_ముగింపు /* !HAVE_SETENV */

#నిర్వచితం_కాకపోతే HAVE_SETLOGIN
పూర్ణాంకం setlogin(స్థిరరాశి అక్షరం *);
#అయితే_ముగింపు /* !HAVE_SETLOGIN */

#నిర్వచితం_కాకపోతే HAVE_INNETGR
పూర్ణాంకం innetgr(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
#అయితే_ముగింపు /* HAVE_INNETGR */

#ఒకవేళ !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
పూర్ణాంకం seteuid(uid_t);
#అయితే_ముగింపు /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#ఒకవేళ !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
పూర్ణాంకం setegid(uid_t);
#అయితే_ముగింపు /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ఒకవేళ !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
స్థిరరాశి అక్షరం *strerror(పూర్ణాంకం);
#అయితే_ముగింపు

#ఒకవేళ !defined(HAVE_SETLINEBUF)
#నిర్వచించు setlinebuf(a)	(setvbuf((a), ఖాళీ, _IOLBF, 0))
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_UTIMES
#నిర్వచితం_కాకపోతే HAVE_STRUCT_TIMEVAL
నిర్మాణం timeval {
	దీర్ఘ tv_sec;
	దీర్ఘ tv_usec;
}
#అయితే_ముగింపు /* HAVE_STRUCT_TIMEVAL */

పూర్ణాంకం utimes(స్థిరరాశి అక్షరం *, నిర్మాణం timeval *);
#అయితే_ముగింపు /* HAVE_UTIMES */

#నిర్వచితం_కాకపోతే HAVE_DIRFD
పూర్ణాంకం dirfd(శూన్య *);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే AT_FDCWD
# define AT_FDCWD (-2)
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_FCHMODAT
పూర్ణాంకం fchmodat(పూర్ణాంకం, స్థిరరాశి అక్షరం *, బహుళకం_t, పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_FCHOWNAT
పూర్ణాంకం fchownat(పూర్ణాంకం, స్థిరరాశి అక్షరం *, uid_t, gid_t, పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితమైతే HAVE_FSTATAT
పూర్ణాంకం fstatat(పూర్ణాంకం, స్థిరరాశి అక్షరం *, నిర్మాణం stat *, పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితమైతే HAVE_UNLINKAT
పూర్ణాంకం unlinkat(పూర్ణాంకం, స్థిరరాశి అక్షరం *, పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_TRUNCATE
పూర్ణాంకం truncate (స్థిరరాశి అక్షరం *, off_t);
#అయితే_ముగింపు /* HAVE_TRUNCATE */

#నిర్వచితం_కాకపోతే HAVE_STRUCT_TIMESPEC
నిర్మాణం timespec {
	time_t	tv_sec;
	దీర్ఘ	tv_nsec;
};
#అయితే_ముగింపు /* !HAVE_STRUCT_TIMESPEC */

#ఒకవేళ !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
పూర్ణాంకం nanosleep(స్థిరరాశి నిర్మాణం timespec *, నిర్మాణం timespec *);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
పూర్ణాంకం utimensat(పూర్ణాంకం, స్థిరరాశి అక్షరం *, స్థిరరాశి నిర్మాణం timespec[2], పూర్ణాంకం);
#అయితే_ముగింపు /* !HAVE_UTIMENSAT */

#నిర్వచితం_కాకపోతే HAVE_USLEEP
పూర్ణాంకం usleep(గుర్తులేని పూర్ణాంకం useconds);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_TCGETPGRP
pid_t tcgetpgrp(పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_TCSENDBREAK
పూర్ణాంకం tcsendbreak(పూర్ణాంకం, పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_UNSETENV
పూర్ణాంకం unsetenv(స్థిరరాశి అక్షరం *);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_ISBLANK
పూర్ణాంకం	isblank(పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_GETPGID
pid_t getpgid(pid_t);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_PSELECT
పూర్ణాంకం pselect(పూర్ణాంకం, fd_set *, fd_set *, fd_set *, స్థిరరాశి నిర్మాణం timespec *,
    స్థిరరాశి sigset_t *);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_ENDGRENT
# define endgrent() చేయి { } అయితే(0)
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_KRB5_GET_ERROR_సందేశం
# define krb5_get_error_సందేశం krb5_get_err_పాఠ్యం
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_KRB5_FREE_ERROR_సందేశం
# define krb5_free_error_సందేశం(a,b) చేయి { } అయితే(0)
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_PLEDGE
పూర్ణాంకం pledge(స్థిరరాశి అక్షరం *promises, స్థిరరాశి అక్షరం *execpromises);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_UNVEIL
పూర్ణాంకం unveil(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
#అయితే_ముగింపు

/* bsd-err.h */
#నిర్వచితం_కాకపోతే HAVE_ERR
శూన్య err(పూర్ణాంకం, స్థిరరాశి అక్షరం *, ...) __attribute__((format(రాయి, 2, 3)));
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే HAVE_ERRX
శూన్య errx(పూర్ణాంకం, స్థిరరాశి అక్షరం *, ...) __attribute__((format(రాయి, 2, 3)));
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే HAVE_WARN
శూన్య warn(స్థిరరాశి అక్షరం *, ...) __attribute__((format(రాయి, 1, 2)));
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_LLABS
దీర్ఘ దీర్ఘ llabs(దీర్ఘ దీర్ఘ);
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
శూన్య bzero(శూన్య *, కొలత_t);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_RAISE
పూర్ణాంకం లేపు(పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_GETSID
pid_t getsid(pid_t);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
పూర్ణాంకం flock(పూర్ణాంకం, పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితమైతే FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_LOCALTIME_R
నిర్మాణం tm *localtime_r(స్థిరరాశి time_t *, నిర్మాణం tm *);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_CLOCK_GETTIME
రకనిర్వచనం పూర్ణాంకం clockid_t;
#నిర్వచితం_కాకపోతే CLOCK_REALTIME
# define CLOCK_REALTIME	0
#అయితే_ముగింపు
పూర్ణాంకం clock_gettime(clockid_t, నిర్మాణం timespec *);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_REALPATH
#నిర్వచించు realpath(x, y)	(sftp_realpath((x), (y)))
#అయితే_ముగింపు

#అయితే_ముగింపు /* _BSD_MISC_H */
