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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_FCNTL_H
# include <fcntl.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) ਲੜੀ_ਲੰਬਾਈ((dirent)->d_name)
#ਨਹੀਂਤਾਂ
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
#ਜੇ_ਅੰਤ
#ਜੇ defined(HAVE_LIBPROC_H)
# include <libproc.h>
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ OPEN_MAX
# define OPEN_MAX	256
#ਜੇ_ਅੰਤ

#ਜੇ 0
__unused ਸਥਿਰ ਅਚਲ ਅੱਖਰ rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#ਜੇ_ਅੰਤ /* lint */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
ਸਥਿਰ ਖਾਲੀ
closefrom_fallback(ਪੂਰਨ lowfd)
{
	ਲੰਮਾ fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#ਨਹੀਂਤਾਂ
	maxfd = getdtablesize();
#ਜੇ_ਅੰਤ /* HAVE_SYSCONF */
	ਜੇ (maxfd < 0)
		maxfd = OPEN_MAX;

	ਲਈ (fd = lowfd; fd < maxfd; fd++)
		(ਖਾਲੀ) close((ਪੂਰਨ) fd);
}
#ਜੇ_ਅੰਤ /* HAVE_FCNTL_CLOSEM */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_FCNTL_CLOSEM
ਖਾਲੀ
closefrom(ਪੂਰਨ lowfd)
{
    (ਖਾਲੀ) fcntl(lowfd, F_CLOSEM, 0);
}
#ਜਾਂਜੇ defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
ਖਾਲੀ
closefrom(ਪੂਰਨ lowfd)
{
	ਪੂਰਨ i, r, sz;
	pid_t pid = getpid();
	ਬਣਤਰ proc_fdinfo *fdinfo_buf = ਨਿਰਾ;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, ਨਿਰਾ, 0);
	ਜੇ (sz == 0)
		ਵਾਪਸ; /* no fds, really? */
	ਨਹੀਂਤਾਂ ਜੇ (sz == -1)
		ਜਾਓ fallback;
	ਜੇ ((fdinfo_buf = ਸਮ੍ਰਿਤੀ_ਦਿਓ(sz)) == ਨਿਰਾ)
		ਜਾਓ fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	ਜੇ (r < 0 || r > sz)
		ਜਾਓ fallback;
	ਲਈ (i = 0; i < r / (ਪੂਰਨ)PROC_PIDLISTFD_ਮਾਪ; i++) {
		ਜੇ (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	ਮੁਕਤ(fdinfo_buf);
	ਵਾਪਸ;
 fallback:
	ਮੁਕਤ(fdinfo_buf);
	closefrom_fallback(lowfd);
	ਵਾਪਸ;
}
#ਜਾਂਜੇ defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
ਖਾਲੀ
closefrom(ਪੂਰਨ lowfd)
{
    ਲੰਮਾ fd;
    ਅੱਖਰ fdpath[PATH_MAX], *endp;
    ਬਣਤਰ dirent *dent;
    DIR *dirp;
    ਪੂਰਨ len;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CLOSE_RANGE
	ਜੇ (close_range(lowfd, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, 0) == 0)
		ਵਾਪਸ;
#ਜੇ_ਅੰਤ

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, ਆਕਾਰ(fdpath), "/proc/%ld/fd", (ਲੰਮਾ)getpid());
    ਜੇ (len > 0 && (ਮਾਪ_t)len < ਆਕਾਰ(fdpath) && (dirp = opendir(fdpath))) {
	ਜਦੋਂ ((dent = readdir(dirp)) != ਨਿਰਾ) {
	    fd = strtol(dent->d_name, &endp, 10);
	    ਜੇ (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ && fd >= lowfd && fd != dirfd(dirp))
		(ਖਾਲੀ) close((ਪੂਰਨ) fd);
	}
	(ਖਾਲੀ) closedir(dirp);
	ਵਾਪਸ;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#ਨਹੀਂਤਾਂ
ਖਾਲੀ
closefrom(ਪੂਰਨ lowfd)
{
	closefrom_fallback(lowfd);
}
#ਜੇ_ਅੰਤ /* !HAVE_FCNTL_CLOSEM */
#ਜੇ_ਅੰਤ /* HAVE_CLOSEFROM */
