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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/ioctl.h>
#ضمن <sys/stat.h>

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <grp.h>
#ضمن <paths.h>
#ضمن <pwd.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <termios.h>
#ضمن <unistd.h>
#ضمن <util.h>

#ضمن "sshpty.h"
#ضمن "log.h"
#ضمن "misc.h"

#ifdef HAVE_PTY_H
# include <pty.h>
#endif

#ifdef __APPLE__
# include <AvailabilityMacros.h>
# 𐡄𐡍 (MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_5)
#  define __APPLE_PRIVPTY__
# endif
#endif

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

صحيح
pty_allocate(صحيح *ptyfd, صحيح *ttyfd, حرف *namebuf, size_t namebuflen)
{
	/* openpty(3) exists in OSF/1 and some other os'es */
	حرف *name;
	صحيح i;

	i = openpty(ptyfd, ttyfd, عدم, عدم, عدم);
	𐡄𐡍 (i == -1) {
		error("openpty: %.100s", strerror(errno));
		أرجع 0;
	}
	name = ttyname(*ttyfd);
	𐡄𐡍 (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	أرجع 1;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

فراغ
pty_release(ثابت حرف *tty)
{
#𐡄𐡍 !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	𐡄𐡍 (chown(tty, (uid_t) 0, (gid_t) 0) == -1)
		error("chown %.100s 0 0 failed: %.100s", tty, strerror(errno));
	𐡄𐡍 (chmod(tty, (mode_t) 0666) == -1)
		error("chmod %.100s 0666 failed: %.100s", tty, strerror(errno));
#endif /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

فراغ
pty_make_controlling_tty(صحيح *ttyfd, ثابت حرف *tty)
{
	صحيح fd;

	/* First disconnect from the old controlling tty. */
#ifdef TIOCNOTTY
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	𐡄𐡍 (fd >= 0) {
		(فراغ) ioctl(fd, TIOCNOTTY, عدم);
		close(fd);
	}
#endif /* TIOCNOTTY */
	𐡄𐡍 (setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	𐡄𐡍 (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		close(fd);
	}
	/* Make it our controlling tty. */
#ifdef TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	𐡄𐡍 (ioctl(*ttyfd, TIOCSCTTY, عدم) < 0)
		error("ioctl(TIOCSCTTY): %.100s", strerror(errno));
#endif /* TIOCSCTTY */
#ifdef NEED_SETPGRP
	𐡄𐡍 (setpgrp(0,0) < 0)
		error("SETPGRP %s",strerror(errno));
#endif /* NEED_SETPGRP */
	fd = open(tty, O_RDWR);
	𐡄𐡍 (fd == -1)
		error("%.100s: %.100s", tty, strerror(errno));
	وإلا
		close(fd);

	/* Verify that we now have a controlling tty. */
	fd = open(_PATH_TTY, O_WRONLY);
	𐡄𐡍 (fd == -1)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    strerror(errno));
	وإلا
		close(fd);
}

/* Changes the window size associated with the pty. */

فراغ
pty_change_window_size(صحيح ptyfd, u_int row, u_int col,
	u_int xpixel, u_int ypixel)
{
	بنية winsize w;

	/* may truncate u_int -> u_short */
	w.ws_row = row;
	w.ws_col = col;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(فراغ) ioctl(ptyfd, TIOCSWINSZ, &w);
}

فراغ
pty_setowner(بنية passwd *pw, ثابت حرف *tty)
{
	بنية group *grp;
	gid_t gid;
	mode_t mode;
	بنية stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	𐡄𐡍 (grp == عدم)
		debug_f("no tty group");
	gid = (grp != عدم) ? grp->gr_gid : pw->pw_gid;
	mode = (grp != عدم) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	𐡄𐡍 (stat(tty, &st) == -1)
		fatal("stat(%.100s) failed: %.100s", tty,
		    strerror(errno));

#ifdef WITH_SELINUX
	ssh_selinux_setup_pty(pw->pw_name, tty);
#endif

	𐡄𐡍 (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		𐡄𐡍 (chown(tty, pw->pw_uid, gid) == -1) {
			𐡄𐡍 (errno == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0))
				debug("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
			وإلا
				fatal("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
		}
	}

	𐡄𐡍 ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != mode) {
		𐡄𐡍 (chmod(tty, mode) == -1) {
			𐡄𐡍 (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
			وإلا
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
		}
	}
}
