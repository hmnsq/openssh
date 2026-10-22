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

#அந்தர்பாவ "includes.h"

#எனில் !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <stdio.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <string.h>
#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#இல்லையெனில்
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
#எனில் defined(HAVE_LIBPROC_H)
# include <libproc.h>
#endif

#ifndef OPEN_MAX
# define OPEN_MAX	256
#endif

#எனில் 0
__unused நிலையான மாறிலி எழுத்து rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#endif /* lint */

#ifndef HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
நிலையான வெறுமை
closefrom_fallback(முழு lowfd)
{
	long fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#ifdef HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#இல்லையெனில்
	maxfd = getdtablesize();
#endif /* HAVE_SYSCONF */
	எனில் (maxfd < 0)
		maxfd = OPEN_MAX;

	க்கு (fd = lowfd; fd < maxfd; fd++)
		(வெறுமை) close((முழு) fd);
}
#endif /* HAVE_FCNTL_CLOSEM */

#ifdef HAVE_FCNTL_CLOSEM
வெறுமை
closefrom(முழு lowfd)
{
    (வெறுமை) fcntl(lowfd, F_CLOSEM, 0);
}
#அல்லதெனில் defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
வெறுமை
closefrom(முழு lowfd)
{
	முழு i, r, sz;
	pid_t pid = getpid();
	கட்டமைப்பு proc_fdinfo *fdinfo_buf = வெற்று;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, வெற்று, 0);
	எனில் (sz == 0)
		திரும்பு; /* no fds, really? */
	இல்லையெனில் எனில் (sz == -1)
		செல் fallback;
	எனில் ((fdinfo_buf = malloc(sz)) == வெற்று)
		செல் fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	எனில் (r < 0 || r > sz)
		செல் fallback;
	க்கு (i = 0; i < r / (முழு)PROC_PIDLISTFD_SIZE; i++) {
		எனில் (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	விடுவி(fdinfo_buf);
	திரும்பு;
 fallback:
	விடுவி(fdinfo_buf);
	closefrom_fallback(lowfd);
	திரும்பு;
}
#அல்லதெனில் defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
வெறுமை
closefrom(முழு lowfd)
{
    long fd;
    எழுத்து fdpath[PATH_MAX], *endp;
    கட்டமைப்பு dirent *dent;
    DIR *dirp;
    முழு len;

#ifdef HAVE_CLOSE_RANGE
	எனில் (close_range(lowfd, INT_MAX, 0) == 0)
		திரும்பு;
#endif

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, அளவு(fdpath), "/proc/%ld/fd", (long)getpid());
    எனில் (len > 0 && (size_t)len < அளவு(fdpath) && (dirp = opendir(fdpath))) {
	போது ((dent = readdir(dirp)) != வெற்று) {
	    fd = strtol(dent->d_name, &endp, 10);
	    எனில் (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < INT_MAX && fd >= lowfd && fd != dirfd(dirp))
		(வெறுமை) close((முழு) fd);
	}
	(வெறுமை) closedir(dirp);
	திரும்பு;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#இல்லையெனில்
வெறுமை
closefrom(முழு lowfd)
{
	closefrom_fallback(lowfd);
}
#endif /* !HAVE_FCNTL_CLOSEM */
#endif /* HAVE_CLOSEFROM */
