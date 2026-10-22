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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/ioctl.h>
#شامل <sys/stat.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <grp.h>
#شامل <paths.h>
#شامل <pwd.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <termios.h>
#شامل <unistd.h>
#شامل <util.h>

#شامل "sshpty.h"
#شامل "log.h"
#شامل "misc.h"

#اگر_تعریف_شدہ HAVE_PTY_H
# include <pty.h>
#اگر_ختم

#اگر_تعریف_شدہ __APPLE__
# include <AvailabilityMacros.h>
# اگر (MAC_OS_X_نسخہ_MAX_ALLOWED >= MAC_OS_X_نسخہ_10_5)
#  define __APPLE_PRIVPTY__
# endif
#اگر_ختم

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

صحیح
pty_allocate(صحیح *ptyfd, صحیح *ttyfd, حرف *namebuf, سائز_t namebuflen)
{
	/* openpty(3) exists in OSF/1 and some other os'es */
	حرف *name;
	صحیح i;

	i = openpty(ptyfd, ttyfd, تہی, تہی, تہی);
	اگر (i == -1) {
		error("openpty: %.100s", strerror(errno));
		واپس 0;
	}
	name = ttyname(*ttyfd);
	اگر (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	واپس 1;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

خالی
pty_release(ثابت حرف *tty)
{
#اگر !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	اگر (chown(tty, (uid_t) 0, (gid_t) 0) == -1)
		error("chown %.100s 0 0 failed: %.100s", tty, strerror(errno));
	اگر (chmod(tty, (منوال_t) 0666) == -1)
		error("chmod %.100s 0666 failed: %.100s", tty, strerror(errno));
#اگر_ختم /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

خالی
pty_make_controlling_tty(صحیح *ttyfd, ثابت حرف *tty)
{
	صحیح fd;

	/* First disconnect from the old controlling tty. */
#اگر_تعریف_شدہ TIOCNOTTY
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	اگر (fd >= 0) {
		(خالی) ioctl(fd, TIOCNOTTY, تہی);
		close(fd);
	}
#اگر_ختم /* TIOCNOTTY */
	اگر (setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	اگر (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		close(fd);
	}
	/* Make it our controlling tty. */
#اگر_تعریف_شدہ TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	اگر (ioctl(*ttyfd, TIOCSCTTY, تہی) < 0)
		error("ioctl(TIOCSCTTY): %.100s", strerror(errno));
#اگر_ختم /* TIOCSCTTY */
#اگر_تعریف_شدہ NEED_SETPGRP
	اگر (setpgrp(0,0) < 0)
		error("SETPGRP %s",strerror(errno));
#اگر_ختم /* NEED_SETPGRP */
	fd = open(tty, O_RDWR);
	اگر (fd == -1)
		error("%.100s: %.100s", tty, strerror(errno));
	ورنہ
		close(fd);

	/* Verify that we now have a controlling tty. */
	fd = open(_PATH_TTY, O_WRONLY);
	اگر (fd == -1)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    strerror(errno));
	ورنہ
		close(fd);
}

/* Changes the window size associated with the pty. */

خالی
pty_change_کھڑکی_سائز(صحیح ptyfd, u_int صف, u_int ستون,
	u_int xpixel, u_int ypixel)
{
	ساخت winsize w;

	/* may truncate u_int -> u_short */
	w.ws_صف = صف;
	w.ws_ستون = ستون;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(خالی) ioctl(ptyfd, TIOCSWINSZ, &w);
}

خالی
pty_setowner(ساخت passwd *pw, ثابت حرف *tty)
{
	ساخت گروہ *grp;
	gid_t gid;
	منوال_t منوال;
	ساخت stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	اگر (grp == تہی)
		debug_f("no tty group");
	gid = (grp != تہی) ? grp->gr_gid : pw->pw_gid;
	منوال = (grp != تہی) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	اگر (stat(tty, &st) == -1)
		fatal("stat(%.100s) failed: %.100s", tty,
		    strerror(errno));

#اگر_تعریف_شدہ WITH_SELINUX
	ssh_selinux_تیاری_pty(pw->pw_name, tty);
#اگر_ختم

	اگر (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		اگر (chown(tty, pw->pw_uid, gid) == -1) {
			اگر (errno == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0))
				debug("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
			ورنہ
				fatal("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
		}
	}

	اگر ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != منوال) {
		اگر (chmod(tty, منوال) == -1) {
			اگر (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)منوال, strerror(errno));
			ورنہ
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)منوال, strerror(errno));
		}
	}
}
