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

#ضمن "includes.h"

#إذا !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#ضمن <sys/types.h>
#ضمن <unistd.h>
#ضمن <stdio.h>
#جيڪڏهن_وصف_ٿيل HAVE_FCNTL_H
# include <fcntl.h>
#جيڪڏهن_پورو
#ضمن <limits.h>
#ضمن <stdlib.h>
#ضمن <stddef.h>
#ضمن <string.h>
#جيڪڏهن_وصف_ٿيل HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) لڙي_ڊيگهه((dirent)->d_name)
#وإلا
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
#جيڪڏهن_پورو
#إذا defined(HAVE_LIBPROC_H)
# include <libproc.h>
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل OPEN_MAX
# define OPEN_MAX	256
#جيڪڏهن_پورو

#إذا 0
__unused ساكن ثابت حرف rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#جيڪڏهن_پورو /* lint */

#جيڪڏهن_وصف_نه_ٿيل HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
ساكن فراغ
closefrom_fallback(صحيح lowfd)
{
	ڊگهو fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#جيڪڏهن_وصف_ٿيل HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#وإلا
	maxfd = getdtablesize();
#جيڪڏهن_پورو /* HAVE_SYSCONF */
	إذا (maxfd < 0)
		maxfd = OPEN_MAX;

	لكل (fd = lowfd; fd < maxfd; fd++)
		(فراغ) close((صحيح) fd);
}
#جيڪڏهن_پورو /* HAVE_FCNTL_CLOSEM */

#جيڪڏهن_وصف_ٿيل HAVE_FCNTL_CLOSEM
فراغ
closefrom(صحيح lowfd)
{
    (فراغ) fcntl(lowfd, F_CLOSEM, 0);
}
#وإلاإذا defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
فراغ
closefrom(صحيح lowfd)
{
	صحيح i, r, sz;
	pid_t pid = getpid();
	بنية proc_fdinfo *fdinfo_buf = عدم;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, عدم, 0);
	إذا (sz == 0)
		أرجع; /* no fds, really? */
	وإلا إذا (sz == -1)
		اذهب fallback;
	إذا ((fdinfo_buf = يادگيري_ڏيو(sz)) == عدم)
		اذهب fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	إذا (r < 0 || r > sz)
		اذهب fallback;
	لكل (i = 0; i < r / (صحيح)PROC_PIDLISTFD_سائيز; i++) {
		إذا (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	حرر(fdinfo_buf);
	أرجع;
 fallback:
	حرر(fdinfo_buf);
	closefrom_fallback(lowfd);
	أرجع;
}
#وإلاإذا defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
فراغ
closefrom(صحيح lowfd)
{
    ڊگهو fd;
    حرف fdpath[PATH_MAX], *endp;
    بنية dirent *dent;
    DIR *dirp;
    صحيح len;

#جيڪڏهن_وصف_ٿيل HAVE_CLOSE_RANGE
	إذا (close_range(lowfd, وڌ_کان_وڌ_عدد, 0) == 0)
		أرجع;
#جيڪڏهن_پورو

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, حجم(fdpath), "/proc/%ld/fd", (ڊگهو)getpid());
    إذا (len > 0 && (سائيز_t)len < حجم(fdpath) && (dirp = opendir(fdpath))) {
	طالما ((dent = readdir(dirp)) != عدم) {
	    fd = strtol(dent->d_name, &endp, 10);
	    إذا (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < وڌ_کان_وڌ_عدد && fd >= lowfd && fd != dirfd(dirp))
		(فراغ) close((صحيح) fd);
	}
	(فراغ) closedir(dirp);
	أرجع;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#وإلا
فراغ
closefrom(صحيح lowfd)
{
	closefrom_fallback(lowfd);
}
#جيڪڏهن_پورو /* !HAVE_FCNTL_CLOSEM */
#جيڪڏهن_پورو /* HAVE_CLOSEFROM */
