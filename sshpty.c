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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/ioctl.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <grp.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <termios.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <util.h>

#अन्तर्भाव "sshpty.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"

#ifdef HAVE_PTY_H
# include <pty.h>
#endif

#ifdef __APPLE__
# include <AvailabilityMacros.h>
# यदि (MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_5)
#  define __APPLE_PRIVPTY__
# endif
#endif

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

पूर्णाङ्क
pty_allocate(पूर्णाङ्क *ptyfd, पूर्णाङ्क *ttyfd, वर्ण *namebuf, माप_प्रकार namebuflen)
{
	/* openpty(3) exists in OSF/1 and some other os'es */
	वर्ण *name;
	पूर्णाङ्क i;

	i = openpty(ptyfd, ttyfd, रिक्त, रिक्त, रिक्त);
	यदि (i == -1) {
		error("openpty: %.100s", म_त्रुटि(त्रुटि_सं));
		फर्काऊ 0;
	}
	name = ttyname(*ttyfd);
	यदि (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	फर्काऊ 1;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

शून्य
pty_release(अचर वर्ण *tty)
{
#यदि !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	यदि (chown(tty, (uid_t) 0, (gid_t) 0) == -1)
		error("chown %.100s 0 0 failed: %.100s", tty, म_त्रुटि(त्रुटि_सं));
	यदि (chmod(tty, (mode_t) 0666) == -1)
		error("chmod %.100s 0666 failed: %.100s", tty, म_त्रुटि(त्रुटि_सं));
#endif /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

शून्य
pty_make_controlling_tty(पूर्णाङ्क *ttyfd, अचर वर्ण *tty)
{
	पूर्णाङ्क fd;

	/* First disconnect from the old controlling tty. */
#ifdef TIOCNOTTY
	fd = खोलो(_PATH_TTY, O_RDWR | O_NOCTTY);
	यदि (fd >= 0) {
		(शून्य) ioctl(fd, TIOCNOTTY, रिक्त);
		बंद(fd);
	}
#endif /* TIOCNOTTY */
	यदि (setsid() == -1)
		error("setsid: %.100s", म_त्रुटि(त्रुटि_सं));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = खोलो(_PATH_TTY, O_RDWR | O_NOCTTY);
	यदि (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		बंद(fd);
	}
	/* Make it our controlling tty. */
#ifdef TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	यदि (ioctl(*ttyfd, TIOCSCTTY, रिक्त) < 0)
		error("ioctl(TIOCSCTTY): %.100s", म_त्रुटि(त्रुटि_सं));
#endif /* TIOCSCTTY */
#ifdef NEED_SETPGRP
	यदि (setpgrp(0,0) < 0)
		error("SETPGRP %s",म_त्रुटि(त्रुटि_सं));
#endif /* NEED_SETPGRP */
	fd = खोलो(tty, O_RDWR);
	यदि (fd == -1)
		error("%.100s: %.100s", tty, म_त्रुटि(त्रुटि_सं));
	अन्यथा
		बंद(fd);

	/* Verify that we now have a controlling tty. */
	fd = खोलो(_PATH_TTY, O_WRONLY);
	यदि (fd == -1)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    म_त्रुटि(त्रुटि_सं));
	अन्यथा
		बंद(fd);
}

/* Changes the window size associated with the pty. */

शून्य
pty_change_window_size(पूर्णाङ्क ptyfd, u_int row, u_int col,
	u_int xpixel, u_int ypixel)
{
	संरचना winsize w;

	/* may truncate u_int -> u_short */
	w.ws_row = row;
	w.ws_col = col;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(शून्य) ioctl(ptyfd, TIOCSWINSZ, &w);
}

शून्य
pty_setowner(संरचना passwd *pw, अचर वर्ण *tty)
{
	संरचना group *grp;
	gid_t gid;
	mode_t mode;
	संरचना stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	यदि (grp == रिक्त)
		debug_f("no tty group");
	gid = (grp != रिक्त) ? grp->gr_gid : pw->pw_gid;
	mode = (grp != रिक्त) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	यदि (stat(tty, &st) == -1)
		fatal("stat(%.100s) failed: %.100s", tty,
		    म_त्रुटि(त्रुटि_सं));

#ifdef WITH_SELINUX
	ssh_selinux_setup_pty(pw->pw_name, tty);
#endif

	यदि (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		यदि (chown(tty, pw->pw_uid, gid) == -1) {
			यदि (त्रुटि_सं == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0))
				debug("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    म_त्रुटि(त्रुटि_सं));
			अन्यथा
				fatal("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    म_त्रुटि(त्रुटि_सं));
		}
	}

	यदि ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != mode) {
		यदि (chmod(tty, mode) == -1) {
			यदि (त्रुटि_सं == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, म_त्रुटि(त्रुटि_सं));
			अन्यथा
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, म_त्रुटि(त्रुटि_सं));
		}
	}
}
