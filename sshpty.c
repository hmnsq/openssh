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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/ioctl.h>
#અન્તર્ભાવ <sys/stat.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <grp.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <termios.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <util.h>

#અન્તર્ભાવ "sshpty.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"

#ifdef HAVE_PTY_H
# include <pty.h>
#endif

#ifdef __APPLE__
# include <AvailabilityMacros.h>
# જો (MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_5)
#  define __APPLE_PRIVPTY__
# endif
#endif

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

પૂર્ણાંક
pty_allocate(પૂર્ણાંક *ptyfd, પૂર્ણાંક *ttyfd, અક્ષર *namebuf, size_t namebuflen)
{
	/* openpty(3) exists in OSF/1 and some other os'es */
	અક્ષર *name;
	પૂર્ણાંક i;

	i = openpty(ptyfd, ttyfd, ખાલી, ખાલી, ખાલી);
	જો (i == -1) {
		error("openpty: %.100s", strerror(errno));
		પાછા 0;
	}
	name = ttyname(*ttyfd);
	જો (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	પાછા 1;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

શૂન્ય
pty_release(અચલ અક્ષર *tty)
{
#જો !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	જો (chown(tty, (uid_t) 0, (gid_t) 0) == -1)
		error("chown %.100s 0 0 failed: %.100s", tty, strerror(errno));
	જો (chmod(tty, (mode_t) 0666) == -1)
		error("chmod %.100s 0666 failed: %.100s", tty, strerror(errno));
#endif /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

શૂન્ય
pty_make_controlling_tty(પૂર્ણાંક *ttyfd, અચલ અક્ષર *tty)
{
	પૂર્ણાંક fd;

	/* First disconnect from the old controlling tty. */
#ifdef TIOCNOTTY
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	જો (fd >= 0) {
		(શૂન્ય) ioctl(fd, TIOCNOTTY, ખાલી);
		close(fd);
	}
#endif /* TIOCNOTTY */
	જો (setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	જો (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		close(fd);
	}
	/* Make it our controlling tty. */
#ifdef TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	જો (ioctl(*ttyfd, TIOCSCTTY, ખાલી) < 0)
		error("ioctl(TIOCSCTTY): %.100s", strerror(errno));
#endif /* TIOCSCTTY */
#ifdef NEED_SETPGRP
	જો (setpgrp(0,0) < 0)
		error("SETPGRP %s",strerror(errno));
#endif /* NEED_SETPGRP */
	fd = open(tty, O_RDWR);
	જો (fd == -1)
		error("%.100s: %.100s", tty, strerror(errno));
	નહીંતર
		close(fd);

	/* Verify that we now have a controlling tty. */
	fd = open(_PATH_TTY, O_WRONLY);
	જો (fd == -1)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    strerror(errno));
	નહીંતર
		close(fd);
}

/* Changes the window size associated with the pty. */

શૂન્ય
pty_change_window_size(પૂર્ણાંક ptyfd, u_int row, u_int col,
	u_int xpixel, u_int ypixel)
{
	સંરચના winsize w;

	/* may truncate u_int -> u_short */
	w.ws_row = row;
	w.ws_col = col;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(શૂન્ય) ioctl(ptyfd, TIOCSWINSZ, &w);
}

શૂન્ય
pty_setowner(સંરચના passwd *pw, અચલ અક્ષર *tty)
{
	સંરચના group *grp;
	gid_t gid;
	mode_t mode;
	સંરચના stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	જો (grp == ખાલી)
		debug_f("no tty group");
	gid = (grp != ખાલી) ? grp->gr_gid : pw->pw_gid;
	mode = (grp != ખાલી) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	જો (stat(tty, &st) == -1)
		fatal("stat(%.100s) failed: %.100s", tty,
		    strerror(errno));

#ifdef WITH_SELINUX
	ssh_selinux_setup_pty(pw->pw_name, tty);
#endif

	જો (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		જો (chown(tty, pw->pw_uid, gid) == -1) {
			જો (errno == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0))
				debug("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
			નહીંતર
				fatal("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
		}
	}

	જો ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != mode) {
		જો (chmod(tty, mode) == -1) {
			જો (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
			નહીંતર
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
		}
	}
}
