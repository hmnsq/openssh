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

#شامل "includes.h"

#اگر !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#شامل <sys/types.h>
#شامل <unistd.h>
#شامل <stdio.h>
#اگر_تعریف_شدہ HAVE_FCNTL_H
# include <fcntl.h>
#اگر_ختم
#شامل <limits.h>
#شامل <stdlib.h>
#شامل <stddef.h>
#شامل <string.h>
#اگر_تعریف_شدہ HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) لڑی_لمبائی((dirent)->d_name)
#ورنہ
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
#اگر_ختم
#اگر defined(HAVE_LIBPROC_H)
# include <libproc.h>
#اگر_ختم

#اگر_غیر_تعریف_شدہ OPEN_MAX
# define OPEN_MAX	256
#اگر_ختم

#اگر 0
__unused ساکن ثابت حرف rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#اگر_ختم /* lint */

#اگر_غیر_تعریف_شدہ HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
ساکن خالی
closefrom_fallback(صحیح lowfd)
{
	طویل fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#اگر_تعریف_شدہ HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#ورنہ
	maxfd = getdtablesize();
#اگر_ختم /* HAVE_SYSCONF */
	اگر (maxfd < 0)
		maxfd = OPEN_MAX;

	برائے (fd = lowfd; fd < maxfd; fd++)
		(خالی) close((صحیح) fd);
}
#اگر_ختم /* HAVE_FCNTL_CLOSEM */

#اگر_تعریف_شدہ HAVE_FCNTL_CLOSEM
خالی
closefrom(صحیح lowfd)
{
    (خالی) fcntl(lowfd, F_CLOSEM, 0);
}
#وگرنہ_اگر defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
خالی
closefrom(صحیح lowfd)
{
	صحیح i, r, sz;
	pid_t pid = getpid();
	ساخت proc_fdinfo *fdinfo_buf = تہی;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, تہی, 0);
	اگر (sz == 0)
		واپس; /* no fds, really? */
	ورنہ اگر (sz == -1)
		جاؤ fallback;
	اگر ((fdinfo_buf = حافظہ_دو(sz)) == تہی)
		جاؤ fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	اگر (r < 0 || r > sz)
		جاؤ fallback;
	برائے (i = 0; i < r / (صحیح)PROC_PIDLISTFD_سائز; i++) {
		اگر (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	آزاد(fdinfo_buf);
	واپس;
 fallback:
	آزاد(fdinfo_buf);
	closefrom_fallback(lowfd);
	واپس;
}
#وگرنہ_اگر defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
خالی
closefrom(صحیح lowfd)
{
    طویل fd;
    حرف fdpath[PATH_MAX], *endp;
    ساخت dirent *dent;
    DIR *dirp;
    صحیح len;

#اگر_تعریف_شدہ HAVE_CLOSE_RANGE
	اگر (close_range(lowfd, زیادہ_سے_زیادہ_عدد, 0) == 0)
		واپس;
#اگر_ختم

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, حجم(fdpath), "/proc/%ld/fd", (طویل)getpid());
    اگر (len > 0 && (سائز_t)len < حجم(fdpath) && (dirp = opendir(fdpath))) {
	جب ((dent = readdir(dirp)) != تہی) {
	    fd = strtol(dent->d_name, &endp, 10);
	    اگر (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < زیادہ_سے_زیادہ_عدد && fd >= lowfd && fd != dirfd(dirp))
		(خالی) close((صحیح) fd);
	}
	(خالی) closedir(dirp);
	واپس;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#ورنہ
خالی
closefrom(صحیح lowfd)
{
	closefrom_fallback(lowfd);
}
#اگر_ختم /* !HAVE_FCNTL_CLOSEM */
#اگر_ختم /* HAVE_CLOSEFROM */
