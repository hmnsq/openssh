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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಯದಿ !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#ಅನ್ಯಥಾ
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
#ಯದಿ defined(HAVE_LIBPROC_H)
# include <libproc.h>
#endif

#ifndef OPEN_MAX
# define OPEN_MAX	256
#endif

#ಯದಿ 0
__unused ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#endif /* lint */

#ifndef HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
closefrom_fallback(ಪೂರ್ಣಾಙ್ಕ lowfd)
{
	long fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#ifdef HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#ಅನ್ಯಥಾ
	maxfd = getdtablesize();
#endif /* HAVE_SYSCONF */
	ಯದಿ (maxfd < 0)
		maxfd = OPEN_MAX;

	ಪ್ರತಿ (fd = lowfd; fd < maxfd; fd++)
		(ಶೂನ್ಯ) close((ಪೂರ್ಣಾಙ್ಕ) fd);
}
#endif /* HAVE_FCNTL_CLOSEM */

#ifdef HAVE_FCNTL_CLOSEM
ಶೂನ್ಯ
closefrom(ಪೂರ್ಣಾಙ್ಕ lowfd)
{
    (ಶೂನ್ಯ) fcntl(lowfd, F_CLOSEM, 0);
}
#ನೋಚೇದ್ಯದಿ defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
ಶೂನ್ಯ
closefrom(ಪೂರ್ಣಾಙ್ಕ lowfd)
{
	ಪೂರ್ಣಾಙ್ಕ i, r, sz;
	pid_t pid = getpid();
	ಸಂರಚನಾ proc_fdinfo *fdinfo_buf = ರಿಕ್ತ;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, ರಿಕ್ತ, 0);
	ಯದಿ (sz == 0)
		ಪ್ರತ್ಯಾಗಮ; /* no fds, really? */
	ಅನ್ಯಥಾ ಯದಿ (sz == -1)
		ಗಚ್ಛ fallback;
	ಯದಿ ((fdinfo_buf = malloc(sz)) == ರಿಕ್ತ)
		ಗಚ್ಛ fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	ಯದಿ (r < 0 || r > sz)
		ಗಚ್ಛ fallback;
	ಪ್ರತಿ (i = 0; i < r / (ಪೂರ್ಣಾಙ್ಕ)PROC_PIDLISTFD_SIZE; i++) {
		ಯದಿ (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	ಮುಕ್ತ(fdinfo_buf);
	ಪ್ರತ್ಯಾಗಮ;
 fallback:
	ಮುಕ್ತ(fdinfo_buf);
	closefrom_fallback(lowfd);
	ಪ್ರತ್ಯಾಗಮ;
}
#ನೋಚೇದ್ಯದಿ defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
ಶೂನ್ಯ
closefrom(ಪೂರ್ಣಾಙ್ಕ lowfd)
{
    long fd;
    ವರ್ಣ fdpath[PATH_MAX], *endp;
    ಸಂರಚನಾ dirent *dent;
    DIR *dirp;
    ಪೂರ್ಣಾಙ್ಕ len;

#ifdef HAVE_CLOSE_RANGE
	ಯದಿ (close_range(lowfd, INT_MAX, 0) == 0)
		ಪ್ರತ್ಯಾಗಮ;
#endif

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, ಪರಿಮಾಣ(fdpath), "/proc/%ld/fd", (long)getpid());
    ಯದಿ (len > 0 && (size_t)len < ಪರಿಮಾಣ(fdpath) && (dirp = opendir(fdpath))) {
	ಯಾವತ್ ((dent = readdir(dirp)) != ರಿಕ್ತ) {
	    fd = strtol(dent->d_name, &endp, 10);
	    ಯದಿ (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < INT_MAX && fd >= lowfd && fd != dirfd(dirp))
		(ಶೂನ್ಯ) close((ಪೂರ್ಣಾಙ್ಕ) fd);
	}
	(ಶೂನ್ಯ) closedir(dirp);
	ಪ್ರತ್ಯಾಗಮ;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#ಅನ್ಯಥಾ
ಶೂನ್ಯ
closefrom(ಪೂರ್ಣಾಙ್ಕ lowfd)
{
	closefrom_fallback(lowfd);
}
#endif /* !HAVE_FCNTL_CLOSEM */
#endif /* HAVE_CLOSEFROM */
