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

#अन्तर्भाव "includes.h"

#यदि !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <stdio.h>
#यदि_परिभाषितम् HAVE_FCNTL_H
# include <fcntl.h>
#यदि_अन्तः
#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <string.h>
#यदि_परिभाषितम् HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) वाक्यदैर्घ्यम्((dirent)->d_name)
#अन्यथा
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
#यदि_अन्तः
#यदि defined(HAVE_LIBPROC_H)
# include <libproc.h>
#यदि_अन्तः

#यदि_अपरिभाषितम् OPEN_MAX
# define OPEN_MAX	256
#यदि_अन्तः

#यदि 0
__unused स्थिर ध्रुव वर्ण rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#यदि_अन्तः /* lint */

#यदि_अपरिभाषितम् HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
स्थिर शून्य
closefrom_fallback(पूर्णाङ्क lowfd)
{
	दीर्घ fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#यदि_परिभाषितम् HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#अन्यथा
	maxfd = getdtablesize();
#यदि_अन्तः /* HAVE_SYSCONF */
	यदि (maxfd < 0)
		maxfd = OPEN_MAX;

	प्रति (fd = lowfd; fd < maxfd; fd++)
		(शून्य) close((पूर्णाङ्क) fd);
}
#यदि_अन्तः /* HAVE_FCNTL_CLOSEM */

#यदि_परिभाषितम् HAVE_FCNTL_CLOSEM
शून्य
closefrom(पूर्णाङ्क lowfd)
{
    (शून्य) fcntl(lowfd, F_CLOSEM, 0);
}
#नोचेद्यदि defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
शून्य
closefrom(पूर्णाङ्क lowfd)
{
	पूर्णाङ्क i, r, sz;
	pid_t pid = getpid();
	संरचना proc_fdinfo *fdinfo_buf = रिक्त;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, रिक्त, 0);
	यदि (sz == 0)
		प्रत्यागम; /* no fds, really? */
	अन्यथा यदि (sz == -1)
		गच्छ fallback;
	यदि ((fdinfo_buf = स्मृतिं_देहि(sz)) == रिक्त)
		गच्छ fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	यदि (r < 0 || r > sz)
		गच्छ fallback;
	प्रति (i = 0; i < r / (पूर्णाङ्क)PROC_PIDLISTFD_आकार; i++) {
		यदि (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	मुक्त(fdinfo_buf);
	प्रत्यागम;
 fallback:
	मुक्त(fdinfo_buf);
	closefrom_fallback(lowfd);
	प्रत्यागम;
}
#नोचेद्यदि defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
शून्य
closefrom(पूर्णाङ्क lowfd)
{
    दीर्घ fd;
    वर्ण fdpath[PATH_MAX], *endp;
    संरचना dirent *dent;
    DIR *dirp;
    पूर्णाङ्क len;

#यदि_परिभाषितम् HAVE_CLOSE_RANGE
	यदि (close_range(lowfd, अधिकतम_पूर्णाङ्कः, 0) == 0)
		प्रत्यागम;
#यदि_अन्तः

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, परिमाण(fdpath), "/proc/%ld/fd", (दीर्घ)getpid());
    यदि (len > 0 && (आकार_t)len < परिमाण(fdpath) && (dirp = opendir(fdpath))) {
	यावत् ((dent = readdir(dirp)) != रिक्त) {
	    fd = strtol(dent->d_name, &endp, 10);
	    यदि (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < अधिकतम_पूर्णाङ्कः && fd >= lowfd && fd != dirfd(dirp))
		(शून्य) close((पूर्णाङ्क) fd);
	}
	(शून्य) closedir(dirp);
	प्रत्यागम;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#अन्यथा
शून्य
closefrom(पूर्णाङ्क lowfd)
{
	closefrom_fallback(lowfd);
}
#यदि_अन्तः /* !HAVE_FCNTL_CLOSEM */
#यदि_अन्तः /* HAVE_CLOSEFROM */
