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

#অন্তর্ভাব "includes.h"

#যদি !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <stdio.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <string.h>
#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#অন্যথা
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
#যদি defined(HAVE_LIBPROC_H)
# include <libproc.h>
#endif

#ifndef OPEN_MAX
# define OPEN_MAX	256
#endif

#যদি 0
__unused স্থির ধ্রুব বর্ণ rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#endif /* lint */

#ifndef HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
স্থির শূন্য
closefrom_fallback(পূর্ণাঙ্ক lowfd)
{
	long fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#ifdef HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#অন্যথা
	maxfd = getdtablesize();
#endif /* HAVE_SYSCONF */
	যদি (maxfd < 0)
		maxfd = OPEN_MAX;

	প্রতি (fd = lowfd; fd < maxfd; fd++)
		(শূন্য) close((পূর্ণাঙ্ক) fd);
}
#endif /* HAVE_FCNTL_CLOSEM */

#ifdef HAVE_FCNTL_CLOSEM
শূন্য
closefrom(পূর্ণাঙ্ক lowfd)
{
    (শূন্য) fcntl(lowfd, F_CLOSEM, 0);
}
#নোচেদ্যদি defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
শূন্য
closefrom(পূর্ণাঙ্ক lowfd)
{
	পূর্ণাঙ্ক i, r, sz;
	pid_t pid = getpid();
	সংরচনা proc_fdinfo *fdinfo_buf = রিক্ত;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, রিক্ত, 0);
	যদি (sz == 0)
		প্রত্যাগম; /* no fds, really? */
	অন্যথা যদি (sz == -1)
		গচ্ছ fallback;
	যদি ((fdinfo_buf = malloc(sz)) == রিক্ত)
		গচ্ছ fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	যদি (r < 0 || r > sz)
		গচ্ছ fallback;
	প্রতি (i = 0; i < r / (পূর্ণাঙ্ক)PROC_PIDLISTFD_SIZE; i++) {
		যদি (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	মুক্ত(fdinfo_buf);
	প্রত্যাগম;
 fallback:
	মুক্ত(fdinfo_buf);
	closefrom_fallback(lowfd);
	প্রত্যাগম;
}
#নোচেদ্যদি defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
শূন্য
closefrom(পূর্ণাঙ্ক lowfd)
{
    long fd;
    বর্ণ fdpath[PATH_MAX], *endp;
    সংরচনা dirent *dent;
    DIR *dirp;
    পূর্ণাঙ্ক len;

#ifdef HAVE_CLOSE_RANGE
	যদি (close_range(lowfd, INT_MAX, 0) == 0)
		প্রত্যাগম;
#endif

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, পরিমাণ(fdpath), "/proc/%ld/fd", (long)getpid());
    যদি (len > 0 && (size_t)len < পরিমাণ(fdpath) && (dirp = opendir(fdpath))) {
	যাবত্ ((dent = readdir(dirp)) != রিক্ত) {
	    fd = strtol(dent->d_name, &endp, 10);
	    যদি (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < INT_MAX && fd >= lowfd && fd != dirfd(dirp))
		(শূন্য) close((পূর্ণাঙ্ক) fd);
	}
	(শূন্য) closedir(dirp);
	প্রত্যাগম;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#অন্যথা
শূন্য
closefrom(পূর্ণাঙ্ক lowfd)
{
	closefrom_fallback(lowfd);
}
#endif /* !HAVE_FCNTL_CLOSEM */
#endif /* HAVE_CLOSEFROM */
