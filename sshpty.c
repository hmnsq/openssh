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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/ioctl.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <grp.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <termios.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <util.h>

#ಅನ್ತರ್ಭಾವ "sshpty.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

#ifdef HAVE_PTY_H
# include <pty.h>
#endif

#ifdef __APPLE__
# include <AvailabilityMacros.h>
# ಯದಿ (MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_5)
#  define __APPLE_PRIVPTY__
# endif
#endif

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

ಪೂರ್ಣಾಙ್ಕ
pty_allocate(ಪೂರ್ಣಾಙ್ಕ *ptyfd, ಪೂರ್ಣಾಙ್ಕ *ttyfd, ವರ್ಣ *namebuf, size_t namebuflen)
{
	/* openpty(3) exists in OSF/1 and some other os'es */
	ವರ್ಣ *name;
	ಪೂರ್ಣಾಙ್ಕ i;

	i = openpty(ptyfd, ttyfd, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ);
	ಯದಿ (i == -1) {
		error("openpty: %.100s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	name = ttyname(*ttyfd);
	ಯದಿ (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	ಪ್ರತ್ಯಾಗಮ 1;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

ಶೂನ್ಯ
pty_release(ಧ್ರುವ ವರ್ಣ *tty)
{
#ಯದಿ !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	ಯದಿ (chown(tty, (uid_t) 0, (gid_t) 0) == -1)
		error("chown %.100s 0 0 failed: %.100s", tty, strerror(errno));
	ಯದಿ (chmod(tty, (mode_t) 0666) == -1)
		error("chmod %.100s 0666 failed: %.100s", tty, strerror(errno));
#endif /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

ಶೂನ್ಯ
pty_make_controlling_tty(ಪೂರ್ಣಾಙ್ಕ *ttyfd, ಧ್ರುವ ವರ್ಣ *tty)
{
	ಪೂರ್ಣಾಙ್ಕ fd;

	/* First disconnect from the old controlling tty. */
#ifdef TIOCNOTTY
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	ಯದಿ (fd >= 0) {
		(ಶೂನ್ಯ) ioctl(fd, TIOCNOTTY, ರಿಕ್ತ);
		close(fd);
	}
#endif /* TIOCNOTTY */
	ಯದಿ (setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	ಯದಿ (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		close(fd);
	}
	/* Make it our controlling tty. */
#ifdef TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	ಯದಿ (ioctl(*ttyfd, TIOCSCTTY, ರಿಕ್ತ) < 0)
		error("ioctl(TIOCSCTTY): %.100s", strerror(errno));
#endif /* TIOCSCTTY */
#ifdef NEED_SETPGRP
	ಯದಿ (setpgrp(0,0) < 0)
		error("SETPGRP %s",strerror(errno));
#endif /* NEED_SETPGRP */
	fd = open(tty, O_RDWR);
	ಯದಿ (fd == -1)
		error("%.100s: %.100s", tty, strerror(errno));
	ಅನ್ಯಥಾ
		close(fd);

	/* Verify that we now have a controlling tty. */
	fd = open(_PATH_TTY, O_WRONLY);
	ಯದಿ (fd == -1)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    strerror(errno));
	ಅನ್ಯಥಾ
		close(fd);
}

/* Changes the window size associated with the pty. */

ಶೂನ್ಯ
pty_change_window_size(ಪೂರ್ಣಾಙ್ಕ ptyfd, u_int row, u_int col,
	u_int xpixel, u_int ypixel)
{
	ಸಂರಚನಾ winsize w;

	/* may truncate u_int -> u_short */
	w.ws_row = row;
	w.ws_col = col;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(ಶೂನ್ಯ) ioctl(ptyfd, TIOCSWINSZ, &w);
}

ಶೂನ್ಯ
pty_setowner(ಸಂರಚನಾ passwd *pw, ಧ್ರುವ ವರ್ಣ *tty)
{
	ಸಂರಚನಾ group *grp;
	gid_t gid;
	mode_t mode;
	ಸಂರಚನಾ stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	ಯದಿ (grp == ರಿಕ್ತ)
		debug_f("no tty group");
	gid = (grp != ರಿಕ್ತ) ? grp->gr_gid : pw->pw_gid;
	mode = (grp != ರಿಕ್ತ) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	ಯದಿ (stat(tty, &st) == -1)
		fatal("stat(%.100s) failed: %.100s", tty,
		    strerror(errno));

#ifdef WITH_SELINUX
	ssh_selinux_setup_pty(pw->pw_name, tty);
#endif

	ಯದಿ (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		ಯದಿ (chown(tty, pw->pw_uid, gid) == -1) {
			ಯದಿ (errno == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0))
				debug("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
			ಅನ್ಯಥಾ
				fatal("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
		}
	}

	ಯದಿ ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != mode) {
		ಯದಿ (chmod(tty, mode) == -1) {
			ಯದಿ (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
			ಅನ್ಯಥಾ
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
		}
	}
}
