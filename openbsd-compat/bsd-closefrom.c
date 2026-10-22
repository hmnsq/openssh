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

#include "includes.h"

#만약 !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include <limits.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#아니면
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
#만약 defined(HAVE_LIBPROC_H)
# include <libproc.h>
#endif

#ifndef OPEN_MAX
# define OPEN_MAX	256
#endif

#만약 0
__unused static const char rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#endif /* lint */

#ifndef HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
static void
closefrom_fallback(정수 lowfd)
{
	long fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#ifdef HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#아니면
	maxfd = getdtablesize();
#endif /* HAVE_SYSCONF */
	만약 (maxfd < 0)
		maxfd = OPEN_MAX;

	위해 (fd = lowfd; fd < maxfd; fd++)
		(void) close((정수) fd);
}
#endif /* HAVE_FCNTL_CLOSEM */

#ifdef HAVE_FCNTL_CLOSEM
void
closefrom(정수 lowfd)
{
    (void) fcntl(lowfd, F_CLOSEM, 0);
}
#elif defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
void
closefrom(정수 lowfd)
{
	정수 i, r, sz;
	pid_t pid = getpid();
	struct proc_fdinfo *fdinfo_buf = NULL;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
	만약 (sz == 0)
		반환; /* no fds, really? */
	아니면 만약 (sz == -1)
		goto fallback;
	만약 ((fdinfo_buf = malloc(sz)) == NULL)
		goto fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	만약 (r < 0 || r > sz)
		goto fallback;
	위해 (i = 0; i < r / (정수)PROC_PIDLISTFD_SIZE; i++) {
		만약 (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	free(fdinfo_buf);
	반환;
 fallback:
	free(fdinfo_buf);
	closefrom_fallback(lowfd);
	반환;
}
#elif defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
void
closefrom(정수 lowfd)
{
    long fd;
    char fdpath[PATH_MAX], *endp;
    struct dirent *dent;
    DIR *dirp;
    정수 len;

#ifdef HAVE_CLOSE_RANGE
	만약 (close_range(lowfd, INT_MAX, 0) == 0)
		반환;
#endif

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, sizeof(fdpath), "/proc/%ld/fd", (long)getpid());
    만약 (len > 0 && (size_t)len < sizeof(fdpath) && (dirp = opendir(fdpath))) {
	동안 ((dent = readdir(dirp)) != NULL) {
	    fd = strtol(dent->d_name, &endp, 10);
	    만약 (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < INT_MAX && fd >= lowfd && fd != dirfd(dirp))
		(void) close((정수) fd);
	}
	(void) closedir(dirp);
	반환;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#아니면
void
closefrom(정수 lowfd)
{
	closefrom_fallback(lowfd);
}
#endif /* !HAVE_FCNTL_CLOSEM */
#endif /* HAVE_CLOSEFROM */
