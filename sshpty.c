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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/ioctl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <grp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <termios.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <util.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "sshpty.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_PTY_H
# include <pty.h>
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __APPLE__
# include <AvailabilityMacros.h>
# ਜੇ (MAC_OS_X_ਸੰਸਕਰਣ_MAX_ALLOWED >= MAC_OS_X_ਸੰਸਕਰਣ_10_5)
#  define __APPLE_PRIVPTY__
# endif
#ਜੇ_ਅੰਤ

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

ਪੂਰਨ
pty_allocate(ਪੂਰਨ *ptyfd, ਪੂਰਨ *ttyfd, ਅੱਖਰ *namebuf, ਮਾਪ_t namebuflen)
{
	/* openpty(3) exists in OSF/1 and some other os'es */
	ਅੱਖਰ *name;
	ਪੂਰਨ i;

	i = openpty(ptyfd, ttyfd, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ);
	ਜੇ (i == -1) {
		error("openpty: %.100s", strerror(errno));
		ਵਾਪਸ 0;
	}
	name = ttyname(*ttyfd);
	ਜੇ (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	ਵਾਪਸ 1;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

ਖਾਲੀ
pty_release(ਅਚਲ ਅੱਖਰ *tty)
{
#ਜੇ !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	ਜੇ (chown(tty, (uid_t) 0, (gid_t) 0) == -1)
		error("chown %.100s 0 0 failed: %.100s", tty, strerror(errno));
	ਜੇ (chmod(tty, (ਬਹੁਲਕ_t) 0666) == -1)
		error("chmod %.100s 0666 failed: %.100s", tty, strerror(errno));
#ਜੇ_ਅੰਤ /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

ਖਾਲੀ
pty_make_controlling_tty(ਪੂਰਨ *ttyfd, ਅਚਲ ਅੱਖਰ *tty)
{
	ਪੂਰਨ fd;

	/* First disconnect from the old controlling tty. */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ TIOCNOTTY
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	ਜੇ (fd >= 0) {
		(ਖਾਲੀ) ioctl(fd, TIOCNOTTY, ਨਿਰਾ);
		close(fd);
	}
#ਜੇ_ਅੰਤ /* TIOCNOTTY */
	ਜੇ (setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	ਜੇ (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		close(fd);
	}
	/* Make it our controlling tty. */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	ਜੇ (ioctl(*ttyfd, TIOCSCTTY, ਨਿਰਾ) < 0)
		error("ioctl(TIOCSCTTY): %.100s", strerror(errno));
#ਜੇ_ਅੰਤ /* TIOCSCTTY */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ NEED_SETPGRP
	ਜੇ (setpgrp(0,0) < 0)
		error("SETPGRP %s",strerror(errno));
#ਜੇ_ਅੰਤ /* NEED_SETPGRP */
	fd = open(tty, O_RDWR);
	ਜੇ (fd == -1)
		error("%.100s: %.100s", tty, strerror(errno));
	ਨਹੀਂਤਾਂ
		close(fd);

	/* Verify that we now have a controlling tty. */
	fd = open(_PATH_TTY, O_WRONLY);
	ਜੇ (fd == -1)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    strerror(errno));
	ਨਹੀਂਤਾਂ
		close(fd);
}

/* Changes the window size associated with the pty. */

ਖਾਲੀ
pty_change_ਖਿੜਕੀ_ਮਾਪ(ਪੂਰਨ ptyfd, u_int ਪੰਕਤੀ, u_int ਖਾਨਾ,
	u_int xpixel, u_int ypixel)
{
	ਬਣਤਰ winsize w;

	/* may truncate u_int -> u_short */
	w.ws_ਪੰਕਤੀ = ਪੰਕਤੀ;
	w.ws_ਖਾਨਾ = ਖਾਨਾ;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(ਖਾਲੀ) ioctl(ptyfd, TIOCSWINSZ, &w);
}

ਖਾਲੀ
pty_setowner(ਬਣਤਰ passwd *pw, ਅਚਲ ਅੱਖਰ *tty)
{
	ਬਣਤਰ ਸਮੂਹ *grp;
	gid_t gid;
	ਬਹੁਲਕ_t ਬਹੁਲਕ;
	ਬਣਤਰ stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	ਜੇ (grp == ਨਿਰਾ)
		debug_f("no tty group");
	gid = (grp != ਨਿਰਾ) ? grp->gr_gid : pw->pw_gid;
	ਬਹੁਲਕ = (grp != ਨਿਰਾ) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	ਜੇ (stat(tty, &st) == -1)
		fatal("stat(%.100s) failed: %.100s", tty,
		    strerror(errno));

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_SELINUX
	ssh_selinux_ਤਿਆਰੀ_pty(pw->pw_name, tty);
#ਜੇ_ਅੰਤ

	ਜੇ (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		ਜੇ (chown(tty, pw->pw_uid, gid) == -1) {
			ਜੇ (errno == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0))
				debug("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
			ਨਹੀਂਤਾਂ
				fatal("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
		}
	}

	ਜੇ ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != ਬਹੁਲਕ) {
		ਜੇ (chmod(tty, ਬਹੁਲਕ) == -1) {
			ਜੇ (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)ਬਹੁਲਕ, strerror(errno));
			ਨਹੀਂਤਾਂ
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)ਬਹੁਲਕ, strerror(errno));
		}
	}
}
