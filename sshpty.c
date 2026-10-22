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

#جے_تعریف_شدہ HAVE_PTY_H
# include <pty.h>
#جے_انت

#جے_تعریف_شدہ __APPLE__
# include <AvailabilityMacros.h>
# إذا (MAC_OS_X_نسخہ_MAX_ALLOWED >= MAC_OS_X_نسخہ_10_5)
#  define __APPLE_PRIVPTY__
# endif
#جے_انت

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

صحيح
pty_allocate(صحيح *ptyfd, صحيح *ttyfd, حرف *namebuf, ناپ_t namebuflen)
{
	/* openpty(3) exists in OSF/1 and some other os'es */
	حرف *name;
	صحيح i;

	i = openpty(ptyfd, ttyfd, عدم, عدم, عدم);
	إذا (i == -1) {
		error("openpty: %.100s", strerror(errno));
		أرجع 0;
	}
	name = ttyname(*ttyfd);
	إذا (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	أرجع 1;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

فراغ
pty_release(ثابت حرف *tty)
{
#إذا !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	إذا (chown(tty, (uid_t) 0, (gid_t) 0) == -1)
		error("chown %.100s 0 0 failed: %.100s", tty, strerror(errno));
	إذا (chmod(tty, (منوال_t) 0666) == -1)
		error("chmod %.100s 0666 failed: %.100s", tty, strerror(errno));
#جے_انت /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

فراغ
pty_make_controlling_tty(صحيح *ttyfd, ثابت حرف *tty)
{
	صحيح fd;

	/* First disconnect from the old controlling tty. */
#جے_تعریف_شدہ TIOCNOTTY
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	إذا (fd >= 0) {
		(فراغ) ioctl(fd, TIOCNOTTY, عدم);
		close(fd);
	}
#جے_انت /* TIOCNOTTY */
	إذا (setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	إذا (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		close(fd);
	}
	/* Make it our controlling tty. */
#جے_تعریف_شدہ TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	إذا (ioctl(*ttyfd, TIOCSCTTY, عدم) < 0)
		error("ioctl(TIOCSCTTY): %.100s", strerror(errno));
#جے_انت /* TIOCSCTTY */
#جے_تعریف_شدہ NEED_SETPGRP
	إذا (setpgrp(0,0) < 0)
		error("SETPGRP %s",strerror(errno));
#جے_انت /* NEED_SETPGRP */
	fd = open(tty, O_RDWR);
	إذا (fd == -1)
		error("%.100s: %.100s", tty, strerror(errno));
	وإلا
		close(fd);

	/* Verify that we now have a controlling tty. */
	fd = open(_PATH_TTY, O_WRONLY);
	إذا (fd == -1)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    strerror(errno));
	وإلا
		close(fd);
}

/* Changes the window size associated with the pty. */

فراغ
pty_change_کھڑکی_ناپ(صحيح ptyfd, u_int صف, u_int خانہ,
	u_int xpixel, u_int ypixel)
{
	بنية winsize w;

	/* may truncate u_int -> u_short */
	w.ws_صف = صف;
	w.ws_خانہ = خانہ;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(فراغ) ioctl(ptyfd, TIOCSWINSZ, &w);
}

فراغ
pty_setowner(بنية passwd *pw, ثابت حرف *tty)
{
	بنية گروہ *grp;
	gid_t gid;
	منوال_t منوال;
	بنية stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	إذا (grp == عدم)
		debug_f("no tty group");
	gid = (grp != عدم) ? grp->gr_gid : pw->pw_gid;
	منوال = (grp != عدم) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	إذا (stat(tty, &st) == -1)
		fatal("stat(%.100s) failed: %.100s", tty,
		    strerror(errno));

#جے_تعریف_شدہ WITH_SELINUX
	ssh_selinux_تیاری_pty(pw->pw_name, tty);
#جے_انت

	إذا (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		إذا (chown(tty, pw->pw_uid, gid) == -1) {
			إذا (errno == EROFS &&
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

	إذا ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != منوال) {
		إذا (chmod(tty, منوال) == -1) {
			إذا (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)منوال, strerror(errno));
			وإلا
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)منوال, strerror(errno));
		}
	}
}
