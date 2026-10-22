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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଯଦି !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#ଅନ୍ୟଥା
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
#ଯଦି defined(HAVE_LIBPROC_H)
# include <libproc.h>
#endif

#ifndef OPEN_MAX
# define OPEN_MAX	256
#endif

#ଯଦି 0
__unused ସ୍ଥିର ଅଚଳ ଅକ୍ଷର rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#endif /* lint */

#ifndef HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
ସ୍ଥିର ଶୂନ୍ୟ
closefrom_fallback(ପୂର୍ଣ୍ଣସଂଖ୍ୟା lowfd)
{
	long fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#ifdef HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#ଅନ୍ୟଥା
	maxfd = getdtablesize();
#endif /* HAVE_SYSCONF */
	ଯଦି (maxfd < 0)
		maxfd = OPEN_MAX;

	ପାଇଁ (fd = lowfd; fd < maxfd; fd++)
		(ଶୂନ୍ୟ) close((ପୂର୍ଣ୍ଣସଂଖ୍ୟା) fd);
}
#endif /* HAVE_FCNTL_CLOSEM */

#ifdef HAVE_FCNTL_CLOSEM
ଶୂନ୍ୟ
closefrom(ପୂର୍ଣ୍ଣସଂଖ୍ୟା lowfd)
{
    (ଶୂନ୍ୟ) fcntl(lowfd, F_CLOSEM, 0);
}
#ନଚେତଯଦି defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
ଶୂନ୍ୟ
closefrom(ପୂର୍ଣ୍ଣସଂଖ୍ୟା lowfd)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r, sz;
	pid_t pid = getpid();
	ସଂରଚନା proc_fdinfo *fdinfo_buf = ଖାଲି;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, ଖାଲି, 0);
	ଯଦି (sz == 0)
		ଫେରନ୍ତୁ; /* no fds, really? */
	ଅନ୍ୟଥା ଯଦି (sz == -1)
		ଯାଅ fallback;
	ଯଦି ((fdinfo_buf = malloc(sz)) == ଖାଲି)
		ଯାଅ fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	ଯଦି (r < 0 || r > sz)
		ଯାଅ fallback;
	ପାଇଁ (i = 0; i < r / (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)PROC_PIDLISTFD_SIZE; i++) {
		ଯଦି (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	ମୁକ୍ତ(fdinfo_buf);
	ଫେରନ୍ତୁ;
 fallback:
	ମୁକ୍ତ(fdinfo_buf);
	closefrom_fallback(lowfd);
	ଫେରନ୍ତୁ;
}
#ନଚେତଯଦି defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
ଶୂନ୍ୟ
closefrom(ପୂର୍ଣ୍ଣସଂଖ୍ୟା lowfd)
{
    long fd;
    ଅକ୍ଷର fdpath[PATH_MAX], *endp;
    ସଂରଚନା dirent *dent;
    DIR *dirp;
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା len;

#ifdef HAVE_CLOSE_RANGE
	ଯଦି (close_range(lowfd, INT_MAX, 0) == 0)
		ଫେରନ୍ତୁ;
#endif

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, ଆକାର(fdpath), "/proc/%ld/fd", (long)getpid());
    ଯଦି (len > 0 && (size_t)len < ଆକାର(fdpath) && (dirp = opendir(fdpath))) {
	ଯେତେବେଳେ ((dent = readdir(dirp)) != ଖାଲି) {
	    fd = strtol(dent->d_name, &endp, 10);
	    ଯଦି (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < INT_MAX && fd >= lowfd && fd != dirfd(dirp))
		(ଶୂନ୍ୟ) close((ପୂର୍ଣ୍ଣସଂଖ୍ୟା) fd);
	}
	(ଶୂନ୍ୟ) closedir(dirp);
	ଫେରନ୍ତୁ;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#ଅନ୍ୟଥା
ଶୂନ୍ୟ
closefrom(ପୂର୍ଣ୍ଣସଂଖ୍ୟା lowfd)
{
	closefrom_fallback(lowfd);
}
#endif /* !HAVE_FCNTL_CLOSEM */
#endif /* HAVE_CLOSEFROM */
