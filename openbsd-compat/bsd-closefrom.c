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

#जर !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <stdio.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <string.h>
#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) म_माप((dirent)->d_name)
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
#endif
#जर defined(HAVE_LIBPROC_H)
# include <libproc.h>
#endif

#ifndef OPEN_MAX
# define OPEN_MAX	256
#endif

#जर 0
__unused स्थिर स्थिरांक अक्षर rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#endif /* lint */

#ifndef HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
स्थिर शून्य
closefrom_fallback(पूर्णांक lowfd)
{
	दीर्घ fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#ifdef HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#अन्यथा
	maxfd = getdtablesize();
#endif /* HAVE_SYSCONF */
	जर (maxfd < 0)
		maxfd = OPEN_MAX;

	साठी (fd = lowfd; fd < maxfd; fd++)
		(शून्य) बंद((पूर्णांक) fd);
}
#endif /* HAVE_FCNTL_CLOSEM */

#ifdef HAVE_FCNTL_CLOSEM
शून्य
closefrom(पूर्णांक lowfd)
{
    (शून्य) fcntl(lowfd, F_CLOSEM, 0);
}
#किंवाजर defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
शून्य
closefrom(पूर्णांक lowfd)
{
	पूर्णांक i, r, sz;
	pid_t pid = getpid();
	संरचना proc_fdinfo *fdinfo_buf = रिक्त;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, रिक्त, 0);
	जर (sz == 0)
		परत; /* no fds, really? */
	अन्यथा जर (sz == -1)
		जा fallback;
	जर ((fdinfo_buf = दो_स्मृति(sz)) == रिक्त)
		जा fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	जर (r < 0 || r > sz)
		जा fallback;
	साठी (i = 0; i < r / (पूर्णांक)PROC_PIDLISTFD_SIZE; i++) {
		जर (fdinfo_buf[i].proc_fd >= lowfd)
			बंद(fdinfo_buf[i].proc_fd);
	}
	मुक्त(fdinfo_buf);
	परत;
 fallback:
	मुक्त(fdinfo_buf);
	closefrom_fallback(lowfd);
	परत;
}
#किंवाजर defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
शून्य
closefrom(पूर्णांक lowfd)
{
    दीर्घ fd;
    अक्षर fdpath[PATH_MAX], *endp;
    संरचना dirent *dent;
    सूची *dirp;
    पूर्णांक len;

#ifdef HAVE_CLOSE_RANGE
	जर (close_range(lowfd, पूर्णांक_उच्च, 0) == 0)
		परत;
#endif

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, आकार(fdpath), "/proc/%ld/fd", (दीर्घ)getpid());
    जर (len > 0 && (माप_प्रकार)len < आकार(fdpath) && (dirp = सूची_खोलो(fdpath))) {
	पर्यंत ((dent = सूची_पढ़ो(dirp)) != रिक्त) {
	    fd = म_से_दीर्घ(dent->d_name, &endp, 10);
	    जर (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < पूर्णांक_उच्च && fd >= lowfd && fd != dirfd(dirp))
		(शून्य) बंद((पूर्णांक) fd);
	}
	(शून्य) बंद_सूची(dirp);
	परत;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#अन्यथा
शून्य
closefrom(पूर्णांक lowfd)
{
	closefrom_fallback(lowfd);
}
#endif /* !HAVE_FCNTL_CLOSEM */
#endif /* HAVE_CLOSEFROM */
