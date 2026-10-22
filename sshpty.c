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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/ioctl.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <grp.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <termios.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <util.h>

#ଅନ୍ତର୍ଭାଵ "sshpty.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"

#ifdef HAVE_PTY_H
# include <pty.h>
#endif

#ifdef __APPLE__
# include <AvailabilityMacros.h>
# ଯଦି (MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_5)
#  define __APPLE_PRIVPTY__
# endif
#endif

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pty_allocate(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ptyfd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ttyfd, ଅକ୍ଷର *namebuf, size_t namebuflen)
{
	/* openpty(3) exists in OSF/1 and some other os'es */
	ଅକ୍ଷର *name;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	i = openpty(ptyfd, ttyfd, ଖାଲି, ଖାଲି, ଖାଲି);
	ଯଦି (i == -1) {
		error("openpty: %.100s", strerror(errno));
		ଫେରନ୍ତୁ 0;
	}
	name = ttyname(*ttyfd);
	ଯଦି (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	ଫେରନ୍ତୁ 1;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

ଶୂନ୍ୟ
pty_release(ଅଚଳ ଅକ୍ଷର *tty)
{
#ଯଦି !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	ଯଦି (chown(tty, (uid_t) 0, (gid_t) 0) == -1)
		error("chown %.100s 0 0 failed: %.100s", tty, strerror(errno));
	ଯଦି (chmod(tty, (mode_t) 0666) == -1)
		error("chmod %.100s 0666 failed: %.100s", tty, strerror(errno));
#endif /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

ଶୂନ୍ୟ
pty_make_controlling_tty(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ttyfd, ଅଚଳ ଅକ୍ଷର *tty)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;

	/* First disconnect from the old controlling tty. */
#ifdef TIOCNOTTY
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	ଯଦି (fd >= 0) {
		(ଶୂନ୍ୟ) ioctl(fd, TIOCNOTTY, ଖାଲି);
		close(fd);
	}
#endif /* TIOCNOTTY */
	ଯଦି (setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	ଯଦି (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		close(fd);
	}
	/* Make it our controlling tty. */
#ifdef TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	ଯଦି (ioctl(*ttyfd, TIOCSCTTY, ଖାଲି) < 0)
		error("ioctl(TIOCSCTTY): %.100s", strerror(errno));
#endif /* TIOCSCTTY */
#ifdef NEED_SETPGRP
	ଯଦି (setpgrp(0,0) < 0)
		error("SETPGRP %s",strerror(errno));
#endif /* NEED_SETPGRP */
	fd = open(tty, O_RDWR);
	ଯଦି (fd == -1)
		error("%.100s: %.100s", tty, strerror(errno));
	ଅନ୍ୟଥା
		close(fd);

	/* Verify that we now have a controlling tty. */
	fd = open(_PATH_TTY, O_WRONLY);
	ଯଦି (fd == -1)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    strerror(errno));
	ଅନ୍ୟଥା
		close(fd);
}

/* Changes the window size associated with the pty. */

ଶୂନ୍ୟ
pty_change_window_size(ପୂର୍ଣ୍ଣସଂଖ୍ୟା ptyfd, u_int row, u_int col,
	u_int xpixel, u_int ypixel)
{
	ସଂରଚନା winsize w;

	/* may truncate u_int -> u_short */
	w.ws_row = row;
	w.ws_col = col;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(ଶୂନ୍ୟ) ioctl(ptyfd, TIOCSWINSZ, &w);
}

ଶୂନ୍ୟ
pty_setowner(ସଂରଚନା passwd *pw, ଅଚଳ ଅକ୍ଷର *tty)
{
	ସଂରଚନା group *grp;
	gid_t gid;
	mode_t mode;
	ସଂରଚନା stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	ଯଦି (grp == ଖାଲି)
		debug_f("no tty group");
	gid = (grp != ଖାଲି) ? grp->gr_gid : pw->pw_gid;
	mode = (grp != ଖାଲି) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	ଯଦି (stat(tty, &st) == -1)
		fatal("stat(%.100s) failed: %.100s", tty,
		    strerror(errno));

#ifdef WITH_SELINUX
	ssh_selinux_setup_pty(pw->pw_name, tty);
#endif

	ଯଦି (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		ଯଦି (chown(tty, pw->pw_uid, gid) == -1) {
			ଯଦି (errno == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0))
				debug("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
			ଅନ୍ୟଥା
				fatal("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
		}
	}

	ଯଦି ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != mode) {
		ଯଦି (chmod(tty, mode) == -1) {
			ଯଦି (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
			ଅନ୍ୟଥା
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
		}
	}
}
