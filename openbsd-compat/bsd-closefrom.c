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

#समावेश "includes.h"

#अगर !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#समावेश <sys/types.h>
#समावेश <unistd.h>
#समावेश <stdio.h>
#अगर_घोषित HAVE_FCNTL_H
# include <fcntl.h>
#पूर्ण_अगर
#समावेश <limits.h>
#समावेश <stdlib.h>
#समावेश <stddef.h>
#समावेश <string.h>
#अगर_घोषित HAVE_DIRENT_H
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
#पूर्ण_अगर
#अगर defined(HAVE_LIBPROC_H)
# include <libproc.h>
#पूर्ण_अगर

#अगर_अघोषित OPEN_MAX
# define OPEN_MAX	256
#पूर्ण_अगर

#अगर 0
__unused अटल स्थिर अक्षर rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#पूर्ण_अगर /* lint */

#अगर_अघोषित HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
अटल व्योम
closefrom_fallback(पूर्णांक lowfd)
{
	दीर्घ fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#अगर_घोषित HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#अन्यथा
	maxfd = getdtablesize();
#पूर्ण_अगर /* HAVE_SYSCONF */
	अगर (maxfd < 0)
		maxfd = OPEN_MAX;

	क्रम (fd = lowfd; fd < maxfd; fd++)
		(व्योम) बंद((पूर्णांक) fd);
}
#पूर्ण_अगर /* HAVE_FCNTL_CLOSEM */

#अगर_घोषित HAVE_FCNTL_CLOSEM
व्योम
closefrom(पूर्णांक lowfd)
{
    (व्योम) fcntl(lowfd, F_CLOSEM, 0);
}
#या_अगर defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
व्योम
closefrom(पूर्णांक lowfd)
{
	पूर्णांक i, r, sz;
	pid_t pid = getpid();
	काष्ठा proc_fdinfo *fdinfo_buf = शून्य;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, शून्य, 0);
	अगर (sz == 0)
		वापस; /* no fds, really? */
	अन्यथा अगर (sz == -1)
		जाओ fallback;
	अगर ((fdinfo_buf = दो_स्मृति(sz)) == शून्य)
		जाओ fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	अगर (r < 0 || r > sz)
		जाओ fallback;
	क्रम (i = 0; i < r / (पूर्णांक)PROC_PIDLISTFD_आकार; i++) {
		अगर (fdinfo_buf[i].proc_fd >= lowfd)
			बंद(fdinfo_buf[i].proc_fd);
	}
	मुक्त(fdinfo_buf);
	वापस;
 fallback:
	मुक्त(fdinfo_buf);
	closefrom_fallback(lowfd);
	वापस;
}
#या_अगर defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
व्योम
closefrom(पूर्णांक lowfd)
{
    दीर्घ fd;
    अक्षर fdpath[PATH_MAX], *endp;
    काष्ठा dirent *dent;
    सूची *dirp;
    पूर्णांक len;

#अगर_घोषित HAVE_CLOSE_RANGE
	अगर (close_range(lowfd, पूर्णांक_उच्च, 0) == 0)
		वापस;
#पूर्ण_अगर

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, माप(fdpath), "/proc/%ld/fd", (दीर्घ)getpid());
    अगर (len > 0 && (माप_प्रकार)len < माप(fdpath) && (dirp = सूची_खोलो(fdpath))) {
	जबतक ((dent = सूची_पढ़ो(dirp)) != शून्य) {
	    fd = म_से_दीर्घ(dent->d_name, &endp, 10);
	    अगर (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < पूर्णांक_उच्च && fd >= lowfd && fd != dirfd(dirp))
		(व्योम) बंद((पूर्णांक) fd);
	}
	(व्योम) बंद_सूची(dirp);
	वापस;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#अन्यथा
व्योम
closefrom(पूर्णांक lowfd)
{
	closefrom_fallback(lowfd);
}
#पूर्ण_अगर /* !HAVE_FCNTL_CLOSEM */
#पूर्ण_अगर /* HAVE_CLOSEFROM */
