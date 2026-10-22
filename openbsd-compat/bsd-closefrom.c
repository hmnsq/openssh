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

#അന്തര്ഭാവ "includes.h"

#എങ്കിൽ !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <stdio.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <string.h>
#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#അല്ലെങ്കിൽ
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
#എങ്കിൽ defined(HAVE_LIBPROC_H)
# include <libproc.h>
#endif

#ifndef OPEN_MAX
# define OPEN_MAX	256
#endif

#എങ്കിൽ 0
__unused സ്ഥിതം സ്ഥിരം അക്ഷരം rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#endif /* lint */

#ifndef HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
സ്ഥിതം ശൂന്യം
closefrom_fallback(പൂർണ്ണസംഖ്യ lowfd)
{
	long fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#ifdef HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#അല്ലെങ്കിൽ
	maxfd = getdtablesize();
#endif /* HAVE_SYSCONF */
	എങ്കിൽ (maxfd < 0)
		maxfd = OPEN_MAX;

	വേണ്ടി (fd = lowfd; fd < maxfd; fd++)
		(ശൂന്യം) close((പൂർണ്ണസംഖ്യ) fd);
}
#endif /* HAVE_FCNTL_CLOSEM */

#ifdef HAVE_FCNTL_CLOSEM
ശൂന്യം
closefrom(പൂർണ്ണസംഖ്യ lowfd)
{
    (ശൂന്യം) fcntl(lowfd, F_CLOSEM, 0);
}
#അല്ലെങ്കിലെങ്കിൽ defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
ശൂന്യം
closefrom(പൂർണ്ണസംഖ്യ lowfd)
{
	പൂർണ്ണസംഖ്യ i, r, sz;
	pid_t pid = getpid();
	ഘടന proc_fdinfo *fdinfo_buf = ശൂന്യ;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, ശൂന്യ, 0);
	എങ്കിൽ (sz == 0)
		തിരികെ; /* no fds, really? */
	അല്ലെങ്കിൽ എങ്കിൽ (sz == -1)
		പോകുക fallback;
	എങ്കിൽ ((fdinfo_buf = malloc(sz)) == ശൂന്യ)
		പോകുക fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	എങ്കിൽ (r < 0 || r > sz)
		പോകുക fallback;
	വേണ്ടി (i = 0; i < r / (പൂർണ്ണസംഖ്യ)PROC_PIDLISTFD_SIZE; i++) {
		എങ്കിൽ (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	സ്വതന്ത്രം(fdinfo_buf);
	തിരികെ;
 fallback:
	സ്വതന്ത്രം(fdinfo_buf);
	closefrom_fallback(lowfd);
	തിരികെ;
}
#അല്ലെങ്കിലെങ്കിൽ defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
ശൂന്യം
closefrom(പൂർണ്ണസംഖ്യ lowfd)
{
    long fd;
    അക്ഷരം fdpath[PATH_MAX], *endp;
    ഘടന dirent *dent;
    DIR *dirp;
    പൂർണ്ണസംഖ്യ len;

#ifdef HAVE_CLOSE_RANGE
	എങ്കിൽ (close_range(lowfd, INT_MAX, 0) == 0)
		തിരികെ;
#endif

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, വലുപ്പം(fdpath), "/proc/%ld/fd", (long)getpid());
    എങ്കിൽ (len > 0 && (size_t)len < വലുപ്പം(fdpath) && (dirp = opendir(fdpath))) {
	ആകുമ്പോൾ ((dent = readdir(dirp)) != ശൂന്യ) {
	    fd = strtol(dent->d_name, &endp, 10);
	    എങ്കിൽ (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < INT_MAX && fd >= lowfd && fd != dirfd(dirp))
		(ശൂന്യം) close((പൂർണ്ണസംഖ്യ) fd);
	}
	(ശൂന്യം) closedir(dirp);
	തിരികെ;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#അല്ലെങ്കിൽ
ശൂന്യം
closefrom(പൂർണ്ണസംഖ്യ lowfd)
{
	closefrom_fallback(lowfd);
}
#endif /* !HAVE_FCNTL_CLOSEM */
#endif /* HAVE_CLOSEFROM */
