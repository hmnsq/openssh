/* $OpenBSD: sshpty.c,v 1.36 2026/09/15 06:30:58 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Allocating a pseudo-terminal, and making it the controlling tty.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>

#include "sshpty.h"
#include "log.h"
#include "misc.h"

#ifdef HAVE_PTY_H
# include <pty.h>
#endif

#ifdef __APPLE__
# include <AvailabilityMacros.h>
# གལ་ཏེ (MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_5)
#  define __APPLE_PRIVPTY__
# endif
#endif

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

ཧྲིལ
pty_allocate(ཧྲིལ *ptyfd, ཧྲིལ *ttyfd, var_na *namebuf, size_t namebuflen)
{
	/* openpty(3) exists in OSF/1 and some other os'es */
	var_na *name;
	ཧྲིལ i;

	i = openpty(ptyfd, ttyfd, NULL, NULL, NULL);
	གལ་ཏེ (i == -1) {
		error("openpty: %.100s", strerror(errno));
		ཕྱིར 0;
	}
	name = ttyname(*ttyfd);
	གལ་ཏེ (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	ཕྱིར 1;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

void
pty_release(const var_na *tty)
{
#གལ་ཏེ !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	གལ་ཏེ (chown(tty, (uid_t) 0, (gid_t) 0) == -1)
		error("chown %.100s 0 0 failed: %.100s", tty, strerror(errno));
	གལ་ཏེ (chmod(tty, (mode_t) 0666) == -1)
		error("chmod %.100s 0666 failed: %.100s", tty, strerror(errno));
#endif /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

void
pty_make_controlling_tty(ཧྲིལ *ttyfd, const var_na *tty)
{
	ཧྲིལ fd;

	/* First disconnect from the old controlling tty. */
#ifdef TIOCNOTTY
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	གལ་ཏེ (fd >= 0) {
		(void) ioctl(fd, TIOCNOTTY, NULL);
		close(fd);
	}
#endif /* TIOCNOTTY */
	གལ་ཏེ (setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	གལ་ཏེ (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		close(fd);
	}
	/* Make it our controlling tty. */
#ifdef TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	གལ་ཏེ (ioctl(*ttyfd, TIOCSCTTY, NULL) < 0)
		error("ioctl(TIOCSCTTY): %.100s", strerror(errno));
#endif /* TIOCSCTTY */
#ifdef NEED_SETPGRP
	གལ་ཏེ (setpgrp(0,0) < 0)
		error("SETPGRP %s",strerror(errno));
#endif /* NEED_SETPGRP */
	fd = open(tty, O_RDWR);
	གལ་ཏེ (fd == -1)
		error("%.100s: %.100s", tty, strerror(errno));
	དེ་མིན
		close(fd);

	/* Verify that we now have a controlling tty. */
	fd = open(_PATH_TTY, O_WRONLY);
	གལ་ཏེ (fd == -1)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    strerror(errno));
	དེ་མིན
		close(fd);
}

/* Changes the window size associated with the pty. */

void
pty_change_window_size(ཧྲིལ ptyfd, u_int row, u_int col,
	u_int xpixel, u_int ypixel)
{
	sa_nracanaa winsize w;

	/* may truncate u_int -> u_short */
	w.ws_row = row;
	w.ws_col = col;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(void) ioctl(ptyfd, TIOCSWINSZ, &w);
}

void
pty_setowner(sa_nracanaa passwd *pw, const var_na *tty)
{
	sa_nracanaa group *grp;
	gid_t gid;
	mode_t mode;
	sa_nracanaa stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	གལ་ཏེ (grp == NULL)
		debug_f("no tty group");
	gid = (grp != NULL) ? grp->gr_gid : pw->pw_gid;
	mode = (grp != NULL) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	གལ་ཏེ (stat(tty, &st) == -1)
		fatal("stat(%.100s) failed: %.100s", tty,
		    strerror(errno));

#ifdef WITH_SELINUX
	ssh_selinux_setup_pty(pw->pw_name, tty);
#endif

	གལ་ཏེ (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		གལ་ཏེ (chown(tty, pw->pw_uid, gid) == -1) {
			གལ་ཏེ (errno == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0))
				debug("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
			དེ་མིན
				fatal("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
		}
	}

	གལ་ཏེ ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != mode) {
		གལ་ཏེ (chmod(tty, mode) == -1) {
			གལ་ཏེ (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
			དེ་མིན
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
		}
	}
}
