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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/ioctl.h>
#അന്തര്ഭാവ <sys/stat.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <grp.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <termios.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <util.h>

#അന്തര്ഭാവ "sshpty.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"

#ifdef HAVE_PTY_H
# include <pty.h>
#endif

#ifdef __APPLE__
# include <AvailabilityMacros.h>
# എങ്കിൽ (MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_5)
#  define __APPLE_PRIVPTY__
# endif
#endif

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

പൂർണ്ണസംഖ്യ
pty_allocate(പൂർണ്ണസംഖ്യ *ptyfd, പൂർണ്ണസംഖ്യ *ttyfd, അക്ഷരം *namebuf, size_t namebuflen)
{
	/* openpty(3) exists in OSF/1 and some other os'es */
	അക്ഷരം *name;
	പൂർണ്ണസംഖ്യ i;

	i = openpty(ptyfd, ttyfd, ശൂന്യ, ശൂന്യ, ശൂന്യ);
	എങ്കിൽ (i == -1) {
		error("openpty: %.100s", strerror(errno));
		തിരികെ 0;
	}
	name = ttyname(*ttyfd);
	എങ്കിൽ (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	തിരികെ 1;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

ശൂന്യം
pty_release(സ്ഥിരം അക്ഷരം *tty)
{
#എങ്കിൽ !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	എങ്കിൽ (chown(tty, (uid_t) 0, (gid_t) 0) == -1)
		error("chown %.100s 0 0 failed: %.100s", tty, strerror(errno));
	എങ്കിൽ (chmod(tty, (mode_t) 0666) == -1)
		error("chmod %.100s 0666 failed: %.100s", tty, strerror(errno));
#endif /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

ശൂന്യം
pty_make_controlling_tty(പൂർണ്ണസംഖ്യ *ttyfd, സ്ഥിരം അക്ഷരം *tty)
{
	പൂർണ്ണസംഖ്യ fd;

	/* First disconnect from the old controlling tty. */
#ifdef TIOCNOTTY
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	എങ്കിൽ (fd >= 0) {
		(ശൂന്യം) ioctl(fd, TIOCNOTTY, ശൂന്യ);
		close(fd);
	}
#endif /* TIOCNOTTY */
	എങ്കിൽ (setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	എങ്കിൽ (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		close(fd);
	}
	/* Make it our controlling tty. */
#ifdef TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	എങ്കിൽ (ioctl(*ttyfd, TIOCSCTTY, ശൂന്യ) < 0)
		error("ioctl(TIOCSCTTY): %.100s", strerror(errno));
#endif /* TIOCSCTTY */
#ifdef NEED_SETPGRP
	എങ്കിൽ (setpgrp(0,0) < 0)
		error("SETPGRP %s",strerror(errno));
#endif /* NEED_SETPGRP */
	fd = open(tty, O_RDWR);
	എങ്കിൽ (fd == -1)
		error("%.100s: %.100s", tty, strerror(errno));
	അല്ലെങ്കിൽ
		close(fd);

	/* Verify that we now have a controlling tty. */
	fd = open(_PATH_TTY, O_WRONLY);
	എങ്കിൽ (fd == -1)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    strerror(errno));
	അല്ലെങ്കിൽ
		close(fd);
}

/* Changes the window size associated with the pty. */

ശൂന്യം
pty_change_window_size(പൂർണ്ണസംഖ്യ ptyfd, u_int row, u_int col,
	u_int xpixel, u_int ypixel)
{
	ഘടന winsize w;

	/* may truncate u_int -> u_short */
	w.ws_row = row;
	w.ws_col = col;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(ശൂന്യം) ioctl(ptyfd, TIOCSWINSZ, &w);
}

ശൂന്യം
pty_setowner(ഘടന passwd *pw, സ്ഥിരം അക്ഷരം *tty)
{
	ഘടന group *grp;
	gid_t gid;
	mode_t mode;
	ഘടന stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	എങ്കിൽ (grp == ശൂന്യ)
		debug_f("no tty group");
	gid = (grp != ശൂന്യ) ? grp->gr_gid : pw->pw_gid;
	mode = (grp != ശൂന്യ) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	എങ്കിൽ (stat(tty, &st) == -1)
		fatal("stat(%.100s) failed: %.100s", tty,
		    strerror(errno));

#ifdef WITH_SELINUX
	ssh_selinux_setup_pty(pw->pw_name, tty);
#endif

	എങ്കിൽ (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		എങ്കിൽ (chown(tty, pw->pw_uid, gid) == -1) {
			എങ്കിൽ (errno == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0))
				debug("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
			അല്ലെങ്കിൽ
				fatal("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
		}
	}

	എങ്കിൽ ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != mode) {
		എങ്കിൽ (chmod(tty, mode) == -1) {
			എങ്കിൽ (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
			അല്ലെങ്കിൽ
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
		}
	}
}
