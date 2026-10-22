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

#ប្រសិនបើ !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

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
#បើមិនដូច្នេះ
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
#ប្រសិនបើ defined(HAVE_LIBPROC_H)
# include <libproc.h>
#endif

#ifndef OPEN_MAX
# define OPEN_MAX	256
#endif

#ប្រសិនបើ 0
__unused static const var_na rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#endif /* lint */

#ifndef HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
static void
closefrom_fallback(ចំនួនគត់ lowfd)
{
	long fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#ifdef HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#បើមិនដូច្នេះ
	maxfd = getdtablesize();
#endif /* HAVE_SYSCONF */
	ប្រសិនបើ (maxfd < 0)
		maxfd = OPEN_MAX;

	សម្រាប់ (fd = lowfd; fd < maxfd; fd++)
		(void) close((ចំនួនគត់) fd);
}
#endif /* HAVE_FCNTL_CLOSEM */

#ifdef HAVE_FCNTL_CLOSEM
void
closefrom(ចំនួនគត់ lowfd)
{
    (void) fcntl(lowfd, F_CLOSEM, 0);
}
#elif defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
void
closefrom(ចំនួនគត់ lowfd)
{
	ចំនួនគត់ i, r, sz;
	pid_t pid = getpid();
	sa_nracanaa proc_fdinfo *fdinfo_buf = NULL;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
	ប្រសិនបើ (sz == 0)
		ត្រឡប់; /* no fds, really? */
	បើមិនដូច្នេះ ប្រសិនបើ (sz == -1)
		goto fallback;
	ប្រសិនបើ ((fdinfo_buf = malloc(sz)) == NULL)
		goto fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	ប្រសិនបើ (r < 0 || r > sz)
		goto fallback;
	សម្រាប់ (i = 0; i < r / (ចំនួនគត់)PROC_PIDLISTFD_SIZE; i++) {
		ប្រសិនបើ (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	free(fdinfo_buf);
	ត្រឡប់;
 fallback:
	free(fdinfo_buf);
	closefrom_fallback(lowfd);
	ត្រឡប់;
}
#elif defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
void
closefrom(ចំនួនគត់ lowfd)
{
    long fd;
    var_na fdpath[PATH_MAX], *endp;
    sa_nracanaa dirent *dent;
    DIR *dirp;
    ចំនួនគត់ len;

#ifdef HAVE_CLOSE_RANGE
	ប្រសិនបើ (close_range(lowfd, INT_MAX, 0) == 0)
		ត្រឡប់;
#endif

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, parimaa_na(fdpath), "/proc/%ld/fd", (long)getpid());
    ប្រសិនបើ (len > 0 && (size_t)len < parimaa_na(fdpath) && (dirp = opendir(fdpath))) {
	ខណៈពេល ((dent = readdir(dirp)) != NULL) {
	    fd = strtol(dent->d_name, &endp, 10);
	    ប្រសិនបើ (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < INT_MAX && fd >= lowfd && fd != dirfd(dirp))
		(void) close((ចំនួនគត់) fd);
	}
	(void) closedir(dirp);
	ត្រឡប់;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#បើមិនដូច្នេះ
void
closefrom(ចំនួនគត់ lowfd)
{
	closefrom_fallback(lowfd);
}
#endif /* !HAVE_FCNTL_CLOSEM */
#endif /* HAVE_CLOSEFROM */
