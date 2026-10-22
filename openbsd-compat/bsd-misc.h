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

#अगर_अघोषित _BSD_MISC_H
#घोषणा _BSD_MISC_H

#समावेश "includes.h"

अक्षर *ssh_get_progname(अक्षर *);
पूर्णांक seed_from_prngd(अचिन्हित अक्षर *, माप_प्रकार);

#अगर_अघोषित HAVE_SETSID
#घोषणा setsid() setpgrp(0, getpid())
#पूर्ण_अगर /* !HAVE_SETSID */

#अगर_अघोषित HAVE_SETENV
पूर्णांक setenv(स्थिर अक्षर *, स्थिर अक्षर *, पूर्णांक);
#पूर्ण_अगर /* !HAVE_SETENV */

#अगर_अघोषित HAVE_SETLOGIN
पूर्णांक setlogin(स्थिर अक्षर *);
#पूर्ण_अगर /* !HAVE_SETLOGIN */

#अगर_अघोषित HAVE_INNETGR
पूर्णांक innetgr(स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *);
#पूर्ण_अगर /* HAVE_INNETGR */

#अगर !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
पूर्णांक seteuid(uid_t);
#पूर्ण_अगर /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#अगर !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
पूर्णांक setegid(uid_t);
#पूर्ण_अगर /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#अगर !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
स्थिर अक्षर *म_त्रुटि(पूर्णांक);
#पूर्ण_अगर

#अगर !defined(HAVE_SETLINEBUF)
#घोषणा setlinebuf(a)	(रखो_भबफ((a), शून्य, _IOLBF, 0))
#पूर्ण_अगर

#अगर_अघोषित HAVE_UTIMES
#अगर_अघोषित HAVE_STRUCT_TIMEVAL
काष्ठा timeval {
	दीर्घ tv_sec;
	दीर्घ tv_usec;
}
#पूर्ण_अगर /* HAVE_STRUCT_TIMEVAL */

पूर्णांक utimes(स्थिर अक्षर *, काष्ठा timeval *);
#पूर्ण_अगर /* HAVE_UTIMES */

#अगर_अघोषित HAVE_DIRFD
पूर्णांक dirfd(व्योम *);
#पूर्ण_अगर

#अगर_अघोषित AT_FDCWD
# define AT_FDCWD (-2)
#पूर्ण_अगर

#अगर_अघोषित HAVE_FCHMODAT
पूर्णांक fchmodat(पूर्णांक, स्थिर अक्षर *, mode_t, पूर्णांक);
#पूर्ण_अगर

#अगर_अघोषित HAVE_FCHOWNAT
पूर्णांक fchownat(पूर्णांक, स्थिर अक्षर *, uid_t, gid_t, पूर्णांक);
#पूर्ण_अगर

#अगर_घोषित HAVE_FSTATAT
पूर्णांक fstatat(पूर्णांक, स्थिर अक्षर *, काष्ठा stat *, पूर्णांक);
#पूर्ण_अगर

#अगर_घोषित HAVE_UNLINKAT
पूर्णांक unlinkat(पूर्णांक, स्थिर अक्षर *, पूर्णांक);
#पूर्ण_अगर

#अगर_अघोषित HAVE_TRUNCATE
पूर्णांक truncate (स्थिर अक्षर *, off_t);
#पूर्ण_अगर /* HAVE_TRUNCATE */

#अगर_अघोषित HAVE_STRUCT_TIMESPEC
काष्ठा timespec {
	समय_प्रकार	tv_sec;
	दीर्घ	tv_nsec;
};
#पूर्ण_अगर /* !HAVE_STRUCT_TIMESPEC */

#अगर !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
# include <time.h>
पूर्णांक nanosleep(स्थिर काष्ठा timespec *, काष्ठा timespec *);
#पूर्ण_अगर

#अगर_अघोषित HAVE_UTIMENSAT
# include <time.h>
/* start with the high bits and work down to minimise risk of overlap */
# ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x80000000
# endif
पूर्णांक utimensat(पूर्णांक, स्थिर अक्षर *, स्थिर काष्ठा timespec[2], पूर्णांक);
#पूर्ण_अगर /* !HAVE_UTIMENSAT */

#अगर_अघोषित HAVE_USLEEP
पूर्णांक usleep(अचिन्हित पूर्णांक useconds);
#पूर्ण_अगर

#अगर_अघोषित HAVE_TCGETPGRP
pid_t tcgetpgrp(पूर्णांक);
#पूर्ण_अगर

#अगर_अघोषित HAVE_TCSENDBREAK
पूर्णांक tcsendbreak(पूर्णांक, पूर्णांक);
#पूर्ण_अगर

#अगर_अघोषित HAVE_UNSETENV
पूर्णांक unsetenv(स्थिर अक्षर *);
#पूर्ण_अगर

#अगर_अघोषित HAVE_ISBLANK
पूर्णांक	isblank(पूर्णांक);
#पूर्ण_अगर

#अगर_अघोषित HAVE_GETPGID
pid_t getpgid(pid_t);
#पूर्ण_अगर

#अगर_अघोषित HAVE_PSELECT
पूर्णांक pselect(पूर्णांक, fd_set *, fd_set *, fd_set *, स्थिर काष्ठा timespec *,
    स्थिर sigset_t *);
#पूर्ण_अगर

#अगर_अघोषित HAVE_ENDGRENT
# define endgrent() करो { } जबतक(0)
#पूर्ण_अगर

#अगर_अघोषित HAVE_KRB5_GET_ERROR_MESSAGE
# define krb5_get_error_message krb5_get_err_text
#पूर्ण_अगर

#अगर_अघोषित HAVE_KRB5_FREE_ERROR_MESSAGE
# define krb5_free_error_message(a,b) करो { } जबतक(0)
#पूर्ण_अगर

#अगर_अघोषित HAVE_PLEDGE
पूर्णांक pledge(स्थिर अक्षर *promises, स्थिर अक्षर *execpromises);
#पूर्ण_अगर

#अगर_अघोषित HAVE_UNVEIL
पूर्णांक unveil(स्थिर अक्षर *, स्थिर अक्षर *);
#पूर्ण_अगर

/* bsd-err.h */
#अगर_अघोषित HAVE_ERR
व्योम err(पूर्णांक, स्थिर अक्षर *, ...) __attribute__((format(म_लिखो, 2, 3)));
#पूर्ण_अगर
#अगर_अघोषित HAVE_ERRX
व्योम errx(पूर्णांक, स्थिर अक्षर *, ...) __attribute__((format(म_लिखो, 2, 3)));
#पूर्ण_अगर
#अगर_अघोषित HAVE_WARN
व्योम warn(स्थिर अक्षर *, ...) __attribute__((format(म_लिखो, 1, 2)));
#पूर्ण_अगर

#अगर_अघोषित HAVE_LLABS
दीर्घ दीर्घ llabs(दीर्घ दीर्घ);
#पूर्ण_अगर

#अगर defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 0
व्योम bzero(व्योम *, माप_प्रकार);
#पूर्ण_अगर

#अगर_अघोषित HAVE_RAISE
पूर्णांक उठाओ(पूर्णांक);
#पूर्ण_अगर

#अगर_अघोषित HAVE_GETSID
pid_t getsid(pid_t);
#पूर्ण_अगर

#अगर_अघोषित HAVE_FLOCK
# define LOCK_SH		0x01
# define LOCK_EX		0x02
# define LOCK_NB		0x04
# define LOCK_UN		0x08
पूर्णांक flock(पूर्णांक, पूर्णांक);
#पूर्ण_अगर

#अगर_घोषित FFLUSH_NULL_BUG
# define ख_साफ(x)	(_ssh_compat_fflush(x))
#पूर्ण_अगर

#अगर_अघोषित HAVE_LOCALTIME_R
काष्ठा पंचांग *localtime_r(स्थिर समय_प्रकार *, काष्ठा पंचांग *);
#पूर्ण_अगर

#अगर_अघोषित HAVE_CLOCK_GETTIME
प्रकार पूर्णांक clockid_t;
#अगर_अघोषित CLOCK_REALTIME
# define CLOCK_REALTIME	0
#पूर्ण_अगर
पूर्णांक clock_gettime(clockid_t, काष्ठा timespec *);
#पूर्ण_अगर

#अगर_अघोषित HAVE_REALPATH
#घोषणा realpath(x, y)	(sftp_realpath((x), (y)))
#पूर्ण_अगर

#पूर्ण_अगर /* _BSD_MISC_H */
