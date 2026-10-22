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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/ioctl.h>
#অন্তর্ভাৱ <sys/stat.h>

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <grp.h>
#অন্তর্ভাৱ <paths.h>
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <termios.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <util.h>

#অন্তর্ভাৱ "sshpty.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "misc.h"

#ifdef HAVE_PTY_H
# include <pty.h>
#endif

#ifdef __APPLE__
# include <AvailabilityMacros.h>
# যদি (MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_5)
#  define __APPLE_PRIVPTY__
# endif
#endif

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

পূর্ণাঙ্ক
pty_allocate(পূর্ণাঙ্ক *ptyfd, পূর্ণাঙ্ক *ttyfd, ৱর্ণ *namebuf, size_t namebuflen)
{
	/* openpty(3) exists in OSF/1 and some other os'es */
	ৱর্ণ *name;
	পূর্ণাঙ্ক i;

	i = openpty(ptyfd, ttyfd, রিক্ত, রিক্ত, রিক্ত);
	যদি (i == -1) {
		error("openpty: %.100s", strerror(errno));
		ঘূৰাই 0;
	}
	name = ttyname(*ttyfd);
	যদি (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	ঘূৰাই 1;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

শূন্য
pty_release(ধ্রুৱ ৱর্ণ *tty)
{
#যদি !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	যদি (chown(tty, (uid_t) 0, (gid_t) 0) == -1)
		error("chown %.100s 0 0 failed: %.100s", tty, strerror(errno));
	যদি (chmod(tty, (mode_t) 0666) == -1)
		error("chmod %.100s 0666 failed: %.100s", tty, strerror(errno));
#endif /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

শূন্য
pty_make_controlling_tty(পূর্ণাঙ্ক *ttyfd, ধ্রুৱ ৱর্ণ *tty)
{
	পূর্ণাঙ্ক fd;

	/* First disconnect from the old controlling tty. */
#ifdef TIOCNOTTY
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	যদি (fd >= 0) {
		(শূন্য) ioctl(fd, TIOCNOTTY, রিক্ত);
		close(fd);
	}
#endif /* TIOCNOTTY */
	যদি (setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	যদি (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		close(fd);
	}
	/* Make it our controlling tty. */
#ifdef TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	যদি (ioctl(*ttyfd, TIOCSCTTY, রিক্ত) < 0)
		error("ioctl(TIOCSCTTY): %.100s", strerror(errno));
#endif /* TIOCSCTTY */
#ifdef NEED_SETPGRP
	যদি (setpgrp(0,0) < 0)
		error("SETPGRP %s",strerror(errno));
#endif /* NEED_SETPGRP */
	fd = open(tty, O_RDWR);
	যদি (fd == -1)
		error("%.100s: %.100s", tty, strerror(errno));
	অন্যথা
		close(fd);

	/* Verify that we now have a controlling tty. */
	fd = open(_PATH_TTY, O_WRONLY);
	যদি (fd == -1)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    strerror(errno));
	অন্যথা
		close(fd);
}

/* Changes the window size associated with the pty. */

শূন্য
pty_change_window_size(পূর্ণাঙ্ক ptyfd, u_int row, u_int col,
	u_int xpixel, u_int ypixel)
{
	সংরচনা winsize w;

	/* may truncate u_int -> u_short */
	w.ws_row = row;
	w.ws_col = col;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(শূন্য) ioctl(ptyfd, TIOCSWINSZ, &w);
}

শূন্য
pty_setowner(সংরচনা passwd *pw, ধ্রুৱ ৱর্ণ *tty)
{
	সংরচনা group *grp;
	gid_t gid;
	mode_t mode;
	সংরচনা stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	যদি (grp == রিক্ত)
		debug_f("no tty group");
	gid = (grp != রিক্ত) ? grp->gr_gid : pw->pw_gid;
	mode = (grp != রিক্ত) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	যদি (stat(tty, &st) == -1)
		fatal("stat(%.100s) failed: %.100s", tty,
		    strerror(errno));

#ifdef WITH_SELINUX
	ssh_selinux_setup_pty(pw->pw_name, tty);
#endif

	যদি (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		যদি (chown(tty, pw->pw_uid, gid) == -1) {
			যদি (errno == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0))
				debug("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
			অন্যথা
				fatal("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
		}
	}

	যদি ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != mode) {
		যদি (chmod(tty, mode) == -1) {
			যদি (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
			অন্যথা
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
		}
	}
}
