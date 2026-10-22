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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_PTY_H
# include <pty.h>
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __APPLE__
# include <AvailabilityMacros.h>
# ಆದರೆ (MAC_OS_X_ಆವೃತ್ತಿ_MAX_ALLOWED >= MAC_OS_X_ಆವೃತ್ತಿ_10_5)
#  define __APPLE_PRIVPTY__
# endif
#ಆದರೆ_ಅಂತ್ಯ

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

ಪೂರ್ಣಾಂಕ
pty_allocate(ಪೂರ್ಣಾಂಕ *ptyfd, ಪೂರ್ಣಾಂಕ *ttyfd, ಅಕ್ಷರ *namebuf, ಗಾತ್ರ_t namebuflen)
{
	/* openpty(3) exists in OSF/1 and some other os'es */
	ಅಕ್ಷರ *name;
	ಪೂರ್ಣಾಂಕ i;

	i = openpty(ptyfd, ttyfd, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ);
	ಆದರೆ (i == -1) {
		error("openpty: %.100s", strerror(errno));
		ಹಿಂತಿರುಗಿ 0;
	}
	name = ttyname(*ttyfd);
	ಆದರೆ (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	ಹಿಂತಿರುಗಿ 1;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

ಶೂನ್ಯ
pty_release(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *tty)
{
#ಆದರೆ !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	ಆದರೆ (chown(tty, (uid_t) 0, (gid_t) 0) == -1)
		error("chown %.100s 0 0 failed: %.100s", tty, strerror(errno));
	ಆದರೆ (chmod(tty, (ಬಹುಲಕ_t) 0666) == -1)
		error("chmod %.100s 0666 failed: %.100s", tty, strerror(errno));
#ಆದರೆ_ಅಂತ್ಯ /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

ಶೂನ್ಯ
pty_make_controlling_tty(ಪೂರ್ಣಾಂಕ *ttyfd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *tty)
{
	ಪೂರ್ಣಾಂಕ fd;

	/* First disconnect from the old controlling tty. */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ TIOCNOTTY
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	ಆದರೆ (fd >= 0) {
		(ಶೂನ್ಯ) ioctl(fd, TIOCNOTTY, ಖಾಲಿ);
		close(fd);
	}
#ಆದರೆ_ಅಂತ್ಯ /* TIOCNOTTY */
	ಆದರೆ (setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	ಆದರೆ (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		close(fd);
	}
	/* Make it our controlling tty. */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	ಆದರೆ (ioctl(*ttyfd, TIOCSCTTY, ಖಾಲಿ) < 0)
		error("ioctl(TIOCSCTTY): %.100s", strerror(errno));
#ಆದರೆ_ಅಂತ್ಯ /* TIOCSCTTY */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ NEED_SETPGRP
	ಆದರೆ (setpgrp(0,0) < 0)
		error("SETPGRP %s",strerror(errno));
#ಆದರೆ_ಅಂತ್ಯ /* NEED_SETPGRP */
	fd = open(tty, O_RDWR);
	ಆದರೆ (fd == -1)
		error("%.100s: %.100s", tty, strerror(errno));
	ಇಲ್ಲದಿದ್ದರೆ
		close(fd);

	/* Verify that we now have a controlling tty. */
	fd = open(_PATH_TTY, O_WRONLY);
	ಆದರೆ (fd == -1)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    strerror(errno));
	ಇಲ್ಲದಿದ್ದರೆ
		close(fd);
}

/* Changes the window size associated with the pty. */

ಶೂನ್ಯ
pty_change_ಕಿಟಕಿ_ಗಾತ್ರ(ಪೂರ್ಣಾಂಕ ptyfd, u_int ಅಡ್ಡಸಾಲು, u_int ಲಂಬಸಾಲು,
	u_int xpixel, u_int ypixel)
{
	ರಚನೆ winsize w;

	/* may truncate u_int -> u_short */
	w.ws_ಅಡ್ಡಸಾಲು = ಅಡ್ಡಸಾಲು;
	w.ws_ಲಂಬಸಾಲು = ಲಂಬಸಾಲು;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(ಶೂನ್ಯ) ioctl(ptyfd, TIOCSWINSZ, &w);
}

ಶೂನ್ಯ
pty_setowner(ರಚನೆ passwd *pw, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *tty)
{
	ರಚನೆ ಗುಂಪು *grp;
	gid_t gid;
	ಬಹುಲಕ_t ಬಹುಲಕ;
	ರಚನೆ stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	ಆದರೆ (grp == ಖಾಲಿ)
		debug_f("no tty group");
	gid = (grp != ಖಾಲಿ) ? grp->gr_gid : pw->pw_gid;
	ಬಹುಲಕ = (grp != ಖಾಲಿ) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	ಆದರೆ (stat(tty, &st) == -1)
		fatal("stat(%.100s) failed: %.100s", tty,
		    strerror(errno));

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_SELINUX
	ssh_selinux_ಸಿದ್ಧತೆ_pty(pw->pw_name, tty);
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		ಆದರೆ (chown(tty, pw->pw_uid, gid) == -1) {
			ಆದರೆ (errno == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0))
				debug("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
			ಇಲ್ಲದಿದ್ದರೆ
				fatal("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
		}
	}

	ಆದರೆ ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != ಬಹುಲಕ) {
		ಆದರೆ (chmod(tty, ಬಹುಲಕ) == -1) {
			ಆದರೆ (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)ಬಹುಲಕ, strerror(errno));
			ಇಲ್ಲದಿದ್ದರೆ
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)ಬಹುಲಕ, strerror(errno));
		}
	}
}
