/*
 * Please note: this implementation of openpty() is far from complete.
 * it is just enough for portable OpenSSH's needs.
 */

/*
 * Copyright (c) 2004 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
#अगर !defined(HAVE_OPENPTY)

#समावेश <sys/types.h>

#समावेश <stdlib.h>
#समावेश <stdio.h>

#समावेश <sys/stat.h>
#अगर_घोषित HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#पूर्ण_अगर

#अगर_घोषित HAVE_FCNTL_H
# include <fcntl.h>
#पूर्ण_अगर

#समावेश <util.h>

#अगर_घोषित HAVE_PTY_H
# include <pty.h>
#पूर्ण_अगर
#अगर defined(HAVE_DEV_PTMX) && defined(HAVE_SYS_STROPTS_H)
# include <sys/stropts.h>
#पूर्ण_अगर

#समावेश <signal.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "misc.h"
#समावेश "log.h"

#अगर_अघोषित O_NOCTTY
#घोषणा O_NOCTTY 0
#पूर्ण_अगर

#अगर defined(HAVE_DEV_PTMX) && !defined(HAVE__GETPTY)
अटल पूर्णांक
openpty_streams(पूर्णांक *amaster, पूर्णांक *aslave)
{
	/*
	 * This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3
	 * also has bsd-style ptys, but they simply do not work.)
	 */
	पूर्णांक ptm;
	अक्षर *pts;
	sshsig_t old_signal;

	अगर ((ptm = खोलो("/dev/ptmx", O_RDWR | O_NOCTTY)) == -1)
		वापस (-1);

	/* XXX: need to close ptm on error? */
	old_signal = ssh_signal(SIGCHLD, संक_पूर्व);
	अगर (grantpt(ptm) < 0)
		वापस (-1);
	ssh_signal(SIGCHLD, old_signal);

	अगर (unlockpt(ptm) < 0)
		वापस (-1);

	अगर ((pts = ptsname(ptm)) == शून्य)
		वापस (-1);
	*amaster = ptm;

	/* Open the slave side. */
	अगर ((*aslave = खोलो(pts, O_RDWR | O_NOCTTY)) == -1) {
		बंद(*amaster);
		वापस (-1);
	}

# अगर defined(I_FIND) && defined(__SVR4)
	/*
	 * If the streams modules have already been pushed then there
	 * is no more work to do here.
	 */
	अगर (ioctl(*aslave, I_FIND, "ptem") != 0)
		वापस 0;
# endif

	/*
	 * Try to push the appropriate streams modules, as described
	 * in Solaris pts(7).
	 */
	ioctl(*aslave, I_धकेलो, "ptem");
	ioctl(*aslave, I_धकेलो, "ldterm");
# ifndef __hpux
	ioctl(*aslave, I_धकेलो, "ttcompat");
# endif /* __hpux */
	वापस (0);
}
#पूर्ण_अगर

पूर्णांक
openpty(पूर्णांक *amaster, पूर्णांक *aslave, अक्षर *name, स्थिर काष्ठा termios *termp,
   स्थिर काष्ठा winsize *winp)
{
#अगर defined(HAVE__GETPTY)
	/*
	 * _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
	 * pty's automagically when needed
	 */
	अक्षर *slave;

	अगर ((slave = _getpty(amaster, O_RDWR, 0622, 0)) == शून्य)
		वापस (-1);

	/* Open the slave side. */
	अगर ((*aslave = खोलो(slave, O_RDWR | O_NOCTTY)) == -1) {
		बंद(*amaster);
		वापस (-1);
	}
	वापस (0);

#या_अगर defined(HAVE_DEV_PTMX)

#अगर_घोषित SSHD_ACQUIRES_CTTY
	/*
	 * On some (most? all?) SysV based systems with STREAMS based terminals,
	 * sshd will acquire a controlling terminal when it pushes the "ptem"
	 * module.  On such platforms, first allocate a sacrificial pty so
	 * that sshd already has a controlling terminal before allocating the
	 * one that will be passed back to the user process.  This ensures
	 * the second pty is not already the controlling terminal for a
	 * different session and is available to become controlling terminal
	 * for the client's subprocess.  See bugzilla #245 for details.
	 */
	पूर्णांक r, fd;
	अटल पूर्णांक junk_ptyfd = -1, junk_ttyfd;
	अक्षर *junk_name;

	r = openpty_streams(amaster, aslave);
	अगर (junk_ptyfd == -1 && (fd = खोलो(_PATH_TTY, O_RDWR|O_NOCTTY)) >= 0) {
		बंद(fd);
		junk_ptyfd = *amaster;
		junk_ttyfd = *aslave;
		junk_name = ttyname(junk_ttyfd);
		debug("STREAMS bug workaround pty %d tty %d name %s",
		    junk_ptyfd, junk_ttyfd, junk_name ? junk_name : "<none>");
	} अन्यथा
		वापस r;
#पूर्ण_अगर

	वापस openpty_streams(amaster, aslave);

#या_अगर defined(HAVE_DEV_PTS_AND_PTC)
	/* AIX-style pty code. */
	स्थिर अक्षर *ttname;

	अगर ((*amaster = खोलो("/dev/ptc", O_RDWR | O_NOCTTY)) == -1)
		वापस (-1);
	अगर ((ttname = ttyname(*amaster)) == शून्य)
		वापस (-1);
	अगर ((*aslave = खोलो(ttname, O_RDWR | O_NOCTTY)) == -1) {
		बंद(*amaster);
		वापस (-1);
	}
	वापस (0);

#अन्यथा
	/* BSD-style pty code. */
	अक्षर ptbuf[64], ttbuf[64];
	पूर्णांक i;
	स्थिर अक्षर *ptymajors = "pqrstuvwxyzabcdefghijklmno"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	स्थिर अक्षर *ptyminors = "0123456789abcdef";
	पूर्णांक अंक_minors = म_माप(ptyminors);
	पूर्णांक अंक_ptys = म_माप(ptymajors) * अंक_minors;
	काष्ठा termios tio;

	क्रम (i = 0; i < अंक_ptys; i++) {
		snprintf(ptbuf, माप(ptbuf), "/dev/pty%c%c",
		    ptymajors[i / अंक_minors], ptyminors[i % अंक_minors]);
		snprintf(ttbuf, माप(ttbuf), "/dev/tty%c%c",
		    ptymajors[i / अंक_minors], ptyminors[i % अंक_minors]);

		अगर ((*amaster = खोलो(ptbuf, O_RDWR | O_NOCTTY)) == -1) {
			/* Try SCO style naming */
			snprintf(ptbuf, माप(ptbuf), "/dev/ptyp%d", i);
			snprintf(ttbuf, माप(ttbuf), "/dev/ttyp%d", i);
			अगर ((*amaster = खोलो(ptbuf, O_RDWR | O_NOCTTY)) == -1)
				जारी;
		}

		/* Open the slave side. */
		अगर ((*aslave = खोलो(ttbuf, O_RDWR | O_NOCTTY)) == -1) {
			बंद(*amaster);
			वापस (-1);
		}
		/* set tty modes to a sane state for broken clients */
		अगर (tcgetattr(*amaster, &tio) != -1) {
			tio.c_lflag |= (ECHO | ISIG | ICANON);
			tio.c_oflag |= (OPOST | ONLCR);
			tio.c_iflag |= ICRNL;
			tcsetattr(*amaster, TCSANOW, &tio);
		}

		वापस (0);
	}
	वापस (-1);
#पूर्ण_अगर
}

#पूर्ण_अगर /* !defined(HAVE_OPENPTY) */

