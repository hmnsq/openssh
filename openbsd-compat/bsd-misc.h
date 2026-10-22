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

#ifndef _BSD_MISC_H
#define _BSD_MISC_H

#અન્તર્ભાવ "includes.h"

અક્ષર *ssh_get_progname(અક્ષર *);
પૂર્ણાંક seed_from_prngd(unsigned અક્ષર *, size_t);

#ifndef HAVE_SETSID
#define setsid() setpgrp(0, getpid())
#endif /* !HAVE_SETSID */

#ifndef HAVE_SETENV
પૂર્ણાંક setenv(અચલ અક્ષર *, અચલ અક્ષર *, પૂર્ણાંક);
#endif /* !HAVE_SETENV */

#ifndef HAVE_SETLOGIN
પૂર્ણાંક setlogin(અચલ અક્ષર *);
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
પૂર્ણાંક innetgr(અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *);
#endif /* HAVE_INNETGR */

#જો !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
પૂર્ણાંક seteuid(uid_t);
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#જો !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
પૂર્ણાંક setegid(uid_t);
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#જો !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
અચલ અક્ષર *strerror(પૂર્ણાંક);
#endif

#જો !defined(HAVE_SETLINEBUF)
#define setlinebuf(a)	(setvbuf((a), ખાલી, _IOLBF, 0))
#endif

#ifndef HAVE_UTIMES
#ifndef HAVE_STRUCT_TIMEVAL
સંરચના timeval {
	long tv_sec;
	long tv_usec;
}
#endif /* HAVE_STRUCT_TIMEVAL */

પૂર્ણાંક utimes(અચલ અક્ષર *, સંરચના timeval *);
#endif /* HAVE_UTIMES */

#ifndef HAVE_DIRFD
પૂર્ણાંક dirfd(શૂન્ય *);
#endif

#ifndef AT_FDCWD
# define AT_FDCWD (-2)
#endif

#ifndef HAVE_FCHMODAT
પૂર્ણાંક fchmodat(પૂર્ણાંક, અચલ અક્ષર *, mode_t, પૂર્ણાંક);
#endif

#ifndef HAVE_FCHOWNAT
પૂર્ણાંક fchownat(પૂર્ણાંક, અચલ અક્ષર *, uid_t, gid_t, પૂર્ણાંક);
#endif

#ifdef HAVE_FSTATAT
પૂર્ણાંક fstatat(પૂર્ણાંક, અચલ અક્ષર *, સંરચના stat *, પૂર્ણાંક);
#endif

#ifdef HAVE_UNLINKAT
પૂર્ણાંક unlinkat(પૂર્ણાંક, અચલ અક્ષર *, પૂર્ણાંક);
#endif

#ifndef HAVE_TRUNCATE
પૂર્ણાંક truncate (અચલ અક્ષર *, off_t);
#endif /* HAVE_TRUNCATE */

#ifndef HAVE_STRUCT_TIMESPEC
સંરચના timespec {
	time_t	tv_sec;
	long	tv_nsec;
};
#endif /* !HAVE_STRUCT_TIMESPEC */

#જો !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
પૂર્ણાંક nanosleep(અચલ સંરચના timespec *, સંરચના timespec *);
#endif

#ifndef HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
પૂર્ણાંક utimensat(પૂર્ણાંક, અચલ અક્ષર *, અચલ સંરચના timespec[2], પૂર્ણાંક);
#endif /* !HAVE_UTIMENSAT */

#ifndef HAVE_USLEEP
પૂર્ણાંક usleep(unsigned પૂર્ણાંક useconds);
#endif

#ifndef HAVE_TCGETPGRP
pid_t tcgetpgrp(પૂર્ણાંક);
#endif

#ifndef HAVE_TCSENDBREAK
પૂર્ણાંક tcsendbreak(પૂર્ણાંક, પૂર્ણાંક);
#endif

#ifndef HAVE_UNSETENV
પૂર્ણાંક unsetenv(અચલ અક્ષર *);
#endif

#ifndef HAVE_ISBLANK
પૂર્ણાંક	isblank(પૂર્ણાંક);
#endif

#ifndef HAVE_GETPGID
pid_t getpgid(pid_t);
#endif

#ifndef HAVE_PSELECT
પૂર્ણાંક pselect(પૂર્ણાંક, fd_set *, fd_set *, fd_set *, અચલ સંરચના timespec *,
    અચલ sigset_t *);
#endif

#ifndef HAVE_ENDGRENT
# define endgrent() કરો { } જ્યારે(0)
#endif

#ifndef HAVE_KRB5_GET_ERROR_MESSAGE
# define krb5_get_error_message krb5_get_err_text
#endif

#ifndef HAVE_KRB5_FREE_ERROR_MESSAGE
# define krb5_free_error_message(a,b) કરો { } જ્યારે(0)
#endif

#ifndef HAVE_PLEDGE
પૂર્ણાંક pledge(અચલ અક્ષર *promises, અચલ અક્ષર *execpromises);
#endif

#ifndef HAVE_UNVEIL
પૂર્ણાંક unveil(અચલ અક્ષર *, અચલ અક્ષર *);
#endif

/* bsd-err.h */
#ifndef HAVE_ERR
શૂન્ય err(પૂર્ણાંક, અચલ અક્ષર *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_ERRX
શૂન્ય errx(પૂર્ણાંક, અચલ અક્ષર *, ...) __attribute__((format(printf, 2, 3)));
#endif
#ifndef HAVE_WARN
શૂન્ય warn(અચલ અક્ષર *, ...) __attribute__((format(printf, 1, 2)));
#endif

#ifndef HAVE_LLABS
long long llabs(long long);
#endif

#જો defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
શૂન્ય bzero(શૂન્ય *, size_t);
#endif

#ifndef HAVE_RAISE
પૂર્ણાંક ઉઠાવો(પૂર્ણાંક);
#endif

#ifndef HAVE_GETSID
pid_t getsid(pid_t);
#endif

#ifndef HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
પૂર્ણાંક flock(પૂર્ણાંક, પૂર્ણાંક);
#endif

#ifdef FFLUSH_NULL_BUG
# define fflush(x)	(_ssh_compat_fflush(x))
#endif

#ifndef HAVE_LOCALTIME_R
સંરચના tm *localtime_r(અચલ time_t *, સંરચના tm *);
#endif

#ifndef HAVE_CLOCK_GETTIME
પ્રકારવ્યાખ્યા પૂર્ણાંક clockid_t;
#ifndef CLOCK_REALTIME
# define CLOCK_REALTIME	0
#endif
પૂર્ણાંક clock_gettime(clockid_t, સંરચના timespec *);
#endif

#ifndef HAVE_REALPATH
#define realpath(x, y)	(sftp_realpath((x), (y)))
#endif

#endif /* _BSD_MISC_H */
