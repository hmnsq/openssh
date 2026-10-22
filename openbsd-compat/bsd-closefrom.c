/*
 * Copyright (c) 2004-2005 Todd C. Miller <Todd.Miller@courtesan.com>
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

#شامل "includes.h"

#اگر !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#شامل <sys/types.h>
#شامل <unistd.h>
#شامل <stdio.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#شامل <limits.h>
#شامل <stdlib.h>
#شامل <stddef.h>
#شامل <string.h>
#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#وگرنه
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif
#اگر defined(HAVE_LIBPROC_H)
# include <libproc.h>
#endif

#ifndef OPEN_MAX
# define OPEN_MAX	256
#endif

#اگر 0
__unused ایستا ثابت نویسه rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#endif /* lint */

#ifndef HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
ایستا تهی
closefrom_fallback(صحیح lowfd)
{
	long fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#ifdef HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#وگرنه
	maxfd = getdtablesize();
#endif /* HAVE_SYSCONF */
	اگر (maxfd < 0)
		maxfd = OPEN_MAX;

	برای (fd = lowfd; fd < maxfd; fd++)
		(تهی) close((صحیح) fd);
}
#endif /* HAVE_FCNTL_CLOSEM */

#ifdef HAVE_FCNTL_CLOSEM
تهی
closefrom(صحیح lowfd)
{
    (تهی) fcntl(lowfd, F_CLOSEM, 0);
}
#وگرنهاگر defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
تهی
closefrom(صحیح lowfd)
{
	صحیح i, r, sz;
	pid_t pid = getpid();
	ساختار proc_fdinfo *fdinfo_buf = پوچ;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, پوچ, 0);
	اگر (sz == 0)
		بازگشت; /* no fds, really? */
	وگرنه اگر (sz == -1)
		برو fallback;
	اگر ((fdinfo_buf = malloc(sz)) == پوچ)
		برو fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	اگر (r < 0 || r > sz)
		برو fallback;
	برای (i = 0; i < r / (صحیح)PROC_PIDLISTFD_SIZE; i++) {
		اگر (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	آزاد(fdinfo_buf);
	بازگشت;
 fallback:
	آزاد(fdinfo_buf);
	closefrom_fallback(lowfd);
	بازگشت;
}
#وگرنهاگر defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
تهی
closefrom(صحیح lowfd)
{
    long fd;
    نویسه fdpath[PATH_MAX], *endp;
    ساختار dirent *dent;
    DIR *dirp;
    صحیح len;

#ifdef HAVE_CLOSE_RANGE
	اگر (close_range(lowfd, INT_MAX, 0) == 0)
		بازگشت;
#endif

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, اندازه(fdpath), "/proc/%ld/fd", (long)getpid());
    اگر (len > 0 && (size_t)len < اندازه(fdpath) && (dirp = opendir(fdpath))) {
	وقتی ((dent = readdir(dirp)) != پوچ) {
	    fd = strtol(dent->d_name, &endp, 10);
	    اگر (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < INT_MAX && fd >= lowfd && fd != dirfd(dirp))
		(تهی) close((صحیح) fd);
	}
	(تهی) closedir(dirp);
	بازگشت;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#وگرنه
تهی
closefrom(صحیح lowfd)
{
	closefrom_fallback(lowfd);
}
#endif /* !HAVE_FCNTL_CLOSEM */
#endif /* HAVE_CLOSEFROM */
