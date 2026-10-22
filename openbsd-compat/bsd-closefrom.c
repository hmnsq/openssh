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

#అన్తర్భావ "includes.h"

#ఒకవేళ !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <stdio.h>
#నిర్వచితమైతే HAVE_FCNTL_H
# include <fcntl.h>
#అయితే_ముగింపు
#అన్తర్భావ <limits.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stddef.h>
#అన్తర్భావ <string.h>
#నిర్వచితమైతే HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) అక్షరశ్రేణి_పొడవు((dirent)->d_name)
#లేకపోతే
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
#అయితే_ముగింపు
#ఒకవేళ defined(HAVE_LIBPROC_H)
# include <libproc.h>
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే OPEN_MAX
# define OPEN_MAX	256
#అయితే_ముగింపు

#ఒకవేళ 0
__unused స్థిర స్థిరరాశి అక్షరం rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#అయితే_ముగింపు /* lint */

#నిర్వచితం_కాకపోతే HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
స్థిర శూన్య
closefrom_fallback(పూర్ణాంకం lowfd)
{
	దీర్ఘ fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#నిర్వచితమైతే HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#లేకపోతే
	maxfd = getdtablesize();
#అయితే_ముగింపు /* HAVE_SYSCONF */
	ఒకవేళ (maxfd < 0)
		maxfd = OPEN_MAX;

	కొరకు (fd = lowfd; fd < maxfd; fd++)
		(శూన్య) close((పూర్ణాంకం) fd);
}
#అయితే_ముగింపు /* HAVE_FCNTL_CLOSEM */

#నిర్వచితమైతే HAVE_FCNTL_CLOSEM
శూన్య
closefrom(పూర్ణాంకం lowfd)
{
    (శూన్య) fcntl(lowfd, F_CLOSEM, 0);
}
#లేదావేళ defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
శూన్య
closefrom(పూర్ణాంకం lowfd)
{
	పూర్ణాంకం i, r, sz;
	pid_t pid = getpid();
	నిర్మాణం proc_fdinfo *fdinfo_buf = ఖాళీ;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, ఖాళీ, 0);
	ఒకవేళ (sz == 0)
		తిరిగి; /* no fds, really? */
	లేకపోతే ఒకవేళ (sz == -1)
		వెళ్ళు fallback;
	ఒకవేళ ((fdinfo_buf = జ్ఞాపకం_ఇవ్వు(sz)) == ఖాళీ)
		వెళ్ళు fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	ఒకవేళ (r < 0 || r > sz)
		వెళ్ళు fallback;
	కొరకు (i = 0; i < r / (పూర్ణాంకం)PROC_PIDLISTFD_కొలత; i++) {
		ఒకవేళ (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	విడుదల(fdinfo_buf);
	తిరిగి;
 fallback:
	విడుదల(fdinfo_buf);
	closefrom_fallback(lowfd);
	తిరిగి;
}
#లేదావేళ defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
శూన్య
closefrom(పూర్ణాంకం lowfd)
{
    దీర్ఘ fd;
    అక్షరం fdpath[PATH_MAX], *endp;
    నిర్మాణం dirent *dent;
    DIR *dirp;
    పూర్ణాంకం len;

#నిర్వచితమైతే HAVE_CLOSE_RANGE
	ఒకవేళ (close_range(lowfd, గరిష్ఠ_పూర్ణాంకం, 0) == 0)
		తిరిగి;
#అయితే_ముగింపు

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, పరిమాణం(fdpath), "/proc/%ld/fd", (దీర్ఘ)getpid());
    ఒకవేళ (len > 0 && (కొలత_t)len < పరిమాణం(fdpath) && (dirp = opendir(fdpath))) {
	అయితే ((dent = readdir(dirp)) != ఖాళీ) {
	    fd = strtol(dent->d_name, &endp, 10);
	    ఒకవేళ (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < గరిష్ఠ_పూర్ణాంకం && fd >= lowfd && fd != dirfd(dirp))
		(శూన్య) close((పూర్ణాంకం) fd);
	}
	(శూన్య) closedir(dirp);
	తిరిగి;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#లేకపోతే
శూన్య
closefrom(పూర్ణాంకం lowfd)
{
	closefrom_fallback(lowfd);
}
#అయితే_ముగింపు /* !HAVE_FCNTL_CLOSEM */
#అయితే_ముగింపు /* HAVE_CLOSEFROM */
