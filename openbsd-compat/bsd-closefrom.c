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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಆದರೆ !defined(HAVE_CLOSEFROM) || defined(BROKEN_CLOSEFROM)

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FCNTL_H
# include <fcntl.h>
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) ಅಕ್ಷರಸರಣಿ_ಉದ್ದ((dirent)->d_name)
#ಇಲ್ಲದಿದ್ದರೆ
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
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(HAVE_LIBPROC_H)
# include <libproc.h>
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ OPEN_MAX
# define OPEN_MAX	256
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ 0
__unused ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ rcsid[] = "$Sudo: closefrom.c,v 1.11 2006/08/17 15:26:54 millert Exp $";
#ಆದರೆ_ಅಂತ್ಯ /* lint */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FCNTL_CLOSEM
/*
 * Close all file descriptors greater than or equal to lowfd.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
closefrom_fallback(ಪೂರ್ಣಾಂಕ lowfd)
{
	ದೀರ್ಘ fd, maxfd;

	/*
	 * Fall back on sysconf() or getdtablesize().  We avoid checking
	 * resource limits since it is possible to open a file descriptor
	 * and then drop the rlimit such that it is below the open fd.
	 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYSCONF
	maxfd = sysconf(_SC_OPEN_MAX);
#ಇಲ್ಲದಿದ್ದರೆ
	maxfd = getdtablesize();
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_SYSCONF */
	ಆದರೆ (maxfd < 0)
		maxfd = OPEN_MAX;

	ಗಾಗಿ (fd = lowfd; fd < maxfd; fd++)
		(ಶೂನ್ಯ) close((ಪೂರ್ಣಾಂಕ) fd);
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_FCNTL_CLOSEM */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FCNTL_CLOSEM
ಶೂನ್ಯ
closefrom(ಪೂರ್ಣಾಂಕ lowfd)
{
    (ಶೂನ್ಯ) fcntl(lowfd, F_CLOSEM, 0);
}
#ಅಥವಾಆದರೆ defined(HAVE_LIBPROC_H) && defined(HAVE_PROC_PIDINFO)
ಶೂನ್ಯ
closefrom(ಪೂರ್ಣಾಂಕ lowfd)
{
	ಪೂರ್ಣಾಂಕ i, r, sz;
	pid_t pid = getpid();
	ರಚನೆ proc_fdinfo *fdinfo_buf = ಖಾಲಿ;

	sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, ಖಾಲಿ, 0);
	ಆದರೆ (sz == 0)
		ಹಿಂತಿರುಗಿ; /* no fds, really? */
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sz == -1)
		ಹೋಗು fallback;
	ಆದರೆ ((fdinfo_buf = ಸ್ಮರಣೆ_ಕೊಡು(sz)) == ಖಾಲಿ)
		ಹೋಗು fallback;
	r = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo_buf, sz);
	ಆದರೆ (r < 0 || r > sz)
		ಹೋಗು fallback;
	ಗಾಗಿ (i = 0; i < r / (ಪೂರ್ಣಾಂಕ)PROC_PIDLISTFD_ಗಾತ್ರ; i++) {
		ಆದರೆ (fdinfo_buf[i].proc_fd >= lowfd)
			close(fdinfo_buf[i].proc_fd);
	}
	ಬಿಡುಗಡೆ(fdinfo_buf);
	ಹಿಂತಿರುಗಿ;
 fallback:
	ಬಿಡುಗಡೆ(fdinfo_buf);
	closefrom_fallback(lowfd);
	ಹಿಂತಿರುಗಿ;
}
#ಅಥವಾಆದರೆ defined(HAVE_DIRFD) && defined(HAVE_PROC_PID)
ಶೂನ್ಯ
closefrom(ಪೂರ್ಣಾಂಕ lowfd)
{
    ದೀರ್ಘ fd;
    ಅಕ್ಷರ fdpath[PATH_MAX], *endp;
    ರಚನೆ dirent *dent;
    DIR *dirp;
    ಪೂರ್ಣಾಂಕ len;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CLOSE_RANGE
	ಆದರೆ (close_range(lowfd, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, 0) == 0)
		ಹಿಂತಿರುಗಿ;
#ಆದರೆ_ಅಂತ್ಯ

    /* Check for a /proc/$$/fd directory. */
    len = snprintf(fdpath, ಗಾತ್ರ(fdpath), "/proc/%ld/fd", (ದೀರ್ಘ)getpid());
    ಆದರೆ (len > 0 && (ಗಾತ್ರ_t)len < ಗಾತ್ರ(fdpath) && (dirp = opendir(fdpath))) {
	ಆಗ ((dent = readdir(dirp)) != ಖಾಲಿ) {
	    fd = strtol(dent->d_name, &endp, 10);
	    ಆದರೆ (dent->d_name != endp && *endp == '\0' &&
		fd >= 0 && fd < ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ && fd >= lowfd && fd != dirfd(dirp))
		(ಶೂನ್ಯ) close((ಪೂರ್ಣಾಂಕ) fd);
	}
	(ಶೂನ್ಯ) closedir(dirp);
	ಹಿಂತಿರುಗಿ;
    }
    /* /proc/$$/fd strategy failed, fall back to brute force closure */
    closefrom_fallback(lowfd);
}
#ಇಲ್ಲದಿದ್ದರೆ
ಶೂನ್ಯ
closefrom(ಪೂರ್ಣಾಂಕ lowfd)
{
	closefrom_fallback(lowfd);
}
#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_FCNTL_CLOSEM */
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_CLOSEFROM */
