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

#නම් !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

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
#නැතහොත්
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
#නම් defined(HAVE_LIBPROC_H)
# include <libproc.h>
#endif

#ifndef OPEN_MAX
# define OPEN_MAX	256
#endif

#නම් 0
__unused static const var_na rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#endif /* lint */

#ifndef HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
static void
closefrom_fallback(පූර්ණ_සංඛ්‍යා lowfd)
{
	long fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#ifdef HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#නැතහොත්
	maxfd = getdtablesize();
#endif /* HAVE_SYSCONF */
	නම් (maxfd < 0)
		maxfd = OPEN_MAX;

	සඳහා (fd = lowfd; fd < maxfd; fd++)
		(void) close((පූර්ණ_සංඛ්‍යා) fd);
}
#endif /* HAVE_FCNTL_CLOSEM */

#ifdef HAVE_FCNTL_CLOSEM
void
closefrom(පූර්ණ_සංඛ්‍යා lowfd)
{
    (void) fcntl(lowfd, F_CLOSEM, 0);
}
#elif defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
void
closefrom(පූර්ණ_සංඛ්‍යා lowfd)
{
	පූර්ණ_සංඛ්‍යා i, r, sz;
	pid_t pid = getpid();
	sa_nracanaa proc_fdinfo *fdinfo_buf = NULL;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
	නම් (sz == 0)
		ආපසු; /* no fds, really? */
	නැතහොත් නම් (sz == -1)
		goto fallback;
	නම් ((fdinfo_buf = malloc(sz)) == NULL)
		goto fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	නම් (r < 0 || r > sz)
		goto fallback;
	සඳහා (i = 0; i < r / (පූර්ණ_සංඛ්‍යා)PROC_PIDLISTFD_SIZE; i++) {
		නම් (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	free(fdinfo_buf);
	ආපසු;
 fallback:
	free(fdinfo_buf);
	closefrom_fallback(lowfd);
	ආපසු;
}
#elif defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
void
closefrom(පූර්ණ_සංඛ්‍යා lowfd)
{
    long fd;
    var_na fdpath[PATH_MAX], *endp;
    sa_nracanaa dirent *dent;
    DIR *dirp;
    පූර්ණ_සංඛ්‍යා len;

#ifdef HAVE_CLOSE_RANGE
	නම් (close_range(lowfd, INT_MAX, 0) == 0)
		ආපසු;
#endif

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, parimaa_na(fdpath), "/proc/%ld/fd", (long)getpid());
    නම් (len > 0 && (size_t)len < parimaa_na(fdpath) && (dirp = opendir(fdpath))) {
	අතරතුර ((dent = readdir(dirp)) != NULL) {
	    fd = strtol(dent->d_name, &endp, 10);
	    නම් (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < INT_MAX && fd >= lowfd && fd != dirfd(dirp))
		(void) close((පූර්ණ_සංඛ්‍යා) fd);
	}
	(void) closedir(dirp);
	ආපසු;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#නැතහොත්
void
closefrom(පූර්ණ_සංඛ්‍යා lowfd)
{
	closefrom_fallback(lowfd);
}
#endif /* !HAVE_FCNTL_CLOSEM */
#endif /* HAVE_CLOSEFROM */
