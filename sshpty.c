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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/ioctl.h>
#समावेश <sys/stat.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <grp.h>
#समावेश <paths.h>
#समावेश <pwd.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <termios.h>
#समावेश <unistd.h>
#समावेश <util.h>

#समावेश "sshpty.h"
#समावेश "log.h"
#समावेश "misc.h"

#अगर_घोषित HAVE_PTY_H
# include <pty.h>
#पूर्ण_अगर

#अगर_घोषित __APPLE__
# include <AvailabilityMacros.h>
# अगर (MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_5)
#  define __APPLE_PRIVPTY__
# endif
#पूर्ण_अगर

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

पूर्णांक
pty_allocate(पूर्णांक *ptyfd, पूर्णांक *ttyfd, अक्षर *namebuf, माप_प्रकार namebuflen)
{
	/* openpty(3) exists in OSF/1 and some other os'es */
	अक्षर *name;
	पूर्णांक i;

	i = openpty(ptyfd, ttyfd, शून्य, शून्य, शून्य);
	अगर (i == -1) {
		error("openpty: %.100s", म_त्रुटि(त्रुटि_सं));
		वापस 0;
	}
	name = ttyname(*ttyfd);
	अगर (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	वापस 1;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

व्योम
pty_release(स्थिर अक्षर *tty)
{
#अगर !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	अगर (chown(tty, (uid_t) 0, (gid_t) 0) == -1)
		error("chown %.100s 0 0 failed: %.100s", tty, म_त्रुटि(त्रुटि_सं));
	अगर (chmod(tty, (mode_t) 0666) == -1)
		error("chmod %.100s 0666 failed: %.100s", tty, म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

व्योम
pty_make_controlling_tty(पूर्णांक *ttyfd, स्थिर अक्षर *tty)
{
	पूर्णांक fd;

	/* First disconnect from the old controlling tty. */
#अगर_घोषित TIOCNOTTY
	fd = खोलो(_PATH_TTY, O_RDWR | O_NOCTTY);
	अगर (fd >= 0) {
		(व्योम) ioctl(fd, TIOCNOTTY, शून्य);
		बंद(fd);
	}
#पूर्ण_अगर /* TIOCNOTTY */
	अगर (setsid() == -1)
		error("setsid: %.100s", म_त्रुटि(त्रुटि_सं));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = खोलो(_PATH_TTY, O_RDWR | O_NOCTTY);
	अगर (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		बंद(fd);
	}
	/* Make it our controlling tty. */
#अगर_घोषित TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	अगर (ioctl(*ttyfd, TIOCSCTTY, शून्य) < 0)
		error("ioctl(TIOCSCTTY): %.100s", म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर /* TIOCSCTTY */
#अगर_घोषित NEED_SETPGRP
	अगर (setpgrp(0,0) < 0)
		error("SETPGRP %s",म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर /* NEED_SETPGRP */
	fd = खोलो(tty, O_RDWR);
	अगर (fd == -1)
		error("%.100s: %.100s", tty, म_त्रुटि(त्रुटि_सं));
	अन्यथा
		बंद(fd);

	/* Verify that we now have a controlling tty. */
	fd = खोलो(_PATH_TTY, O_WRONLY);
	अगर (fd == -1)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    म_त्रुटि(त्रुटि_सं));
	अन्यथा
		बंद(fd);
}

/* Changes the window size associated with the pty. */

व्योम
pty_change_window_आकार(पूर्णांक ptyfd, u_int row, u_int col,
	u_int xpixel, u_int ypixel)
{
	काष्ठा winsize w;

	/* may truncate u_int -> u_short */
	w.ws_row = row;
	w.ws_col = col;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(व्योम) ioctl(ptyfd, TIOCSWINSZ, &w);
}

व्योम
pty_setowner(काष्ठा passwd *pw, स्थिर अक्षर *tty)
{
	काष्ठा group *grp;
	gid_t gid;
	mode_t mode;
	काष्ठा stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	अगर (grp == शून्य)
		debug_f("no tty group");
	gid = (grp != शून्य) ? grp->gr_gid : pw->pw_gid;
	mode = (grp != शून्य) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	अगर (stat(tty, &st) == -1)
		fatal("stat(%.100s) failed: %.100s", tty,
		    म_त्रुटि(त्रुटि_सं));

#अगर_घोषित WITH_SELINUX
	ssh_selinux_setup_pty(pw->pw_name, tty);
#पूर्ण_अगर

	अगर (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		अगर (chown(tty, pw->pw_uid, gid) == -1) {
			अगर (त्रुटि_सं == EROFS &&
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

	अगर ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != mode) {
		अगर (chmod(tty, mode) == -1) {
			अगर (त्रुटि_सं == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, म_त्रुटि(त्रुटि_सं));
			अन्यथा
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, म_त्रुटि(त्रुटि_सं));
		}
	}
}
