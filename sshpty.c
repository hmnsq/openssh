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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/ioctl.h>
#అన్తర్భావ <sys/stat.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <grp.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <termios.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <util.h>

#అన్తర్భావ "sshpty.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"

#నిర్వచితమైతే HAVE_PTY_H
# include <pty.h>
#అయితే_ముగింపు

#నిర్వచితమైతే __APPLE__
# include <AvailabilityMacros.h>
# ఒకవేళ (MAC_OS_X_సంస్కరణ_MAX_ALLOWED >= MAC_OS_X_సంస్కరణ_10_5)
#  define __APPLE_PRIVPTY__
# endif
#అయితే_ముగింపు

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

పూర్ణాంకం
pty_allocate(పూర్ణాంకం *ptyfd, పూర్ణాంకం *ttyfd, అక్షరం *namebuf, కొలత_t namebuflen)
{
	/* openpty(3) exists in OSF/1 and some other os'es */
	అక్షరం *name;
	పూర్ణాంకం i;

	i = openpty(ptyfd, ttyfd, ఖాళీ, ఖాళీ, ఖాళీ);
	ఒకవేళ (i == -1) {
		error("openpty: %.100s", strerror(errno));
		తిరిగి 0;
	}
	name = ttyname(*ttyfd);
	ఒకవేళ (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	తిరిగి 1;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

శూన్య
pty_release(స్థిరరాశి అక్షరం *tty)
{
#ఒకవేళ !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	ఒకవేళ (chown(tty, (uid_t) 0, (gid_t) 0) == -1)
		error("chown %.100s 0 0 failed: %.100s", tty, strerror(errno));
	ఒకవేళ (chmod(tty, (బహుళకం_t) 0666) == -1)
		error("chmod %.100s 0666 failed: %.100s", tty, strerror(errno));
#అయితే_ముగింపు /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

శూన్య
pty_make_controlling_tty(పూర్ణాంకం *ttyfd, స్థిరరాశి అక్షరం *tty)
{
	పూర్ణాంకం fd;

	/* First disconnect from the old controlling tty. */
#నిర్వచితమైతే TIOCNOTTY
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	ఒకవేళ (fd >= 0) {
		(శూన్య) ioctl(fd, TIOCNOTTY, ఖాళీ);
		close(fd);
	}
#అయితే_ముగింపు /* TIOCNOTTY */
	ఒకవేళ (setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	ఒకవేళ (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		close(fd);
	}
	/* Make it our controlling tty. */
#నిర్వచితమైతే TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	ఒకవేళ (ioctl(*ttyfd, TIOCSCTTY, ఖాళీ) < 0)
		error("ioctl(TIOCSCTTY): %.100s", strerror(errno));
#అయితే_ముగింపు /* TIOCSCTTY */
#నిర్వచితమైతే NEED_SETPGRP
	ఒకవేళ (setpgrp(0,0) < 0)
		error("SETPGRP %s",strerror(errno));
#అయితే_ముగింపు /* NEED_SETPGRP */
	fd = open(tty, O_RDWR);
	ఒకవేళ (fd == -1)
		error("%.100s: %.100s", tty, strerror(errno));
	లేకపోతే
		close(fd);

	/* Verify that we now have a controlling tty. */
	fd = open(_PATH_TTY, O_WRONLY);
	ఒకవేళ (fd == -1)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    strerror(errno));
	లేకపోతే
		close(fd);
}

/* Changes the window size associated with the pty. */

శూన్య
pty_change_కిటికీ_కొలత(పూర్ణాంకం ptyfd, u_int అడ్డువరుస, u_int నిలువు,
	u_int xpixel, u_int ypixel)
{
	నిర్మాణం winsize w;

	/* may truncate u_int -> u_short */
	w.ws_అడ్డువరుస = అడ్డువరుస;
	w.ws_నిలువు = నిలువు;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(శూన్య) ioctl(ptyfd, TIOCSWINSZ, &w);
}

శూన్య
pty_setowner(నిర్మాణం passwd *pw, స్థిరరాశి అక్షరం *tty)
{
	నిర్మాణం సమూహం *grp;
	gid_t gid;
	బహుళకం_t బహుళకం;
	నిర్మాణం stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	ఒకవేళ (grp == ఖాళీ)
		debug_f("no tty group");
	gid = (grp != ఖాళీ) ? grp->gr_gid : pw->pw_gid;
	బహుళకం = (grp != ఖాళీ) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	ఒకవేళ (stat(tty, &st) == -1)
		fatal("stat(%.100s) failed: %.100s", tty,
		    strerror(errno));

#నిర్వచితమైతే WITH_SELINUX
	ssh_selinux_అమరిక_pty(pw->pw_name, tty);
#అయితే_ముగింపు

	ఒకవేళ (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		ఒకవేళ (chown(tty, pw->pw_uid, gid) == -1) {
			ఒకవేళ (errno == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0))
				debug("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
			లేకపోతే
				fatal("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
		}
	}

	ఒకవేళ ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != బహుళకం) {
		ఒకవేళ (chmod(tty, బహుళకం) == -1) {
			ఒకవేళ (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)బహుళకం, strerror(errno));
			లేకపోతే
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)బహుళకం, strerror(errno));
		}
	}
}
