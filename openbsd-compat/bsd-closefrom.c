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

#અન્તર્ભાવ "includes.h"

#જો !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <stdio.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <string.h>
#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#નહીંતર
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
#જો defined(HAVE_LIBPROC_H)
# include <libproc.h>
#endif

#ifndef OPEN_MAX
# define OPEN_MAX	256
#endif

#જો 0
__unused સ્થિર અચલ અક્ષર rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#endif /* lint */

#ifndef HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
સ્થિર શૂન્ય
closefrom_fallback(પૂર્ણાંક lowfd)
{
	long fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#ifdef HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#નહીંતર
	maxfd = getdtablesize();
#endif /* HAVE_SYSCONF */
	જો (maxfd < 0)
		maxfd = OPEN_MAX;

	માટે (fd = lowfd; fd < maxfd; fd++)
		(શૂન્ય) close((પૂર્ણાંક) fd);
}
#endif /* HAVE_FCNTL_CLOSEM */

#ifdef HAVE_FCNTL_CLOSEM
શૂન્ય
closefrom(પૂર્ણાંક lowfd)
{
    (શૂન્ય) fcntl(lowfd, F_CLOSEM, 0);
}
#અથવાજો defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
શૂન્ય
closefrom(પૂર્ણાંક lowfd)
{
	પૂર્ણાંક i, r, sz;
	pid_t pid = getpid();
	સંરચના proc_fdinfo *fdinfo_buf = ખાલી;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, ખાલી, 0);
	જો (sz == 0)
		પાછા; /* no fds, really? */
	નહીંતર જો (sz == -1)
		જાઓ fallback;
	જો ((fdinfo_buf = malloc(sz)) == ખાલી)
		જાઓ fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	જો (r < 0 || r > sz)
		જાઓ fallback;
	માટે (i = 0; i < r / (પૂર્ણાંક)PROC_PIDLISTFD_SIZE; i++) {
		જો (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	મુક્ત(fdinfo_buf);
	પાછા;
 fallback:
	મુક્ત(fdinfo_buf);
	closefrom_fallback(lowfd);
	પાછા;
}
#અથવાજો defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
શૂન્ય
closefrom(પૂર્ણાંક lowfd)
{
    long fd;
    અક્ષર fdpath[PATH_MAX], *endp;
    સંરચના dirent *dent;
    DIR *dirp;
    પૂર્ણાંક len;

#ifdef HAVE_CLOSE_RANGE
	જો (close_range(lowfd, INT_MAX, 0) == 0)
		પાછા;
#endif

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, કદ(fdpath), "/proc/%ld/fd", (long)getpid());
    જો (len > 0 && (size_t)len < કદ(fdpath) && (dirp = opendir(fdpath))) {
	જ્યારે ((dent = readdir(dirp)) != ખાલી) {
	    fd = strtol(dent->d_name, &endp, 10);
	    જો (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < INT_MAX && fd >= lowfd && fd != dirfd(dirp))
		(શૂન્ય) close((પૂર્ણાંક) fd);
	}
	(શૂન્ય) closedir(dirp);
	પાછા;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#નહીંતર
શૂન્ય
closefrom(પૂર્ણાંક lowfd)
{
	closefrom_fallback(lowfd);
}
#endif /* !HAVE_FCNTL_CLOSEM */
#endif /* HAVE_CLOSEFROM */
