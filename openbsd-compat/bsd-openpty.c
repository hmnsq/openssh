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

#अन्तर्भाव "includes.h"
#यदि !defined(HAVE_OPENPTY)

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>

#अन्तर्भाव <sys/stat.h>
#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#अन्तर्भाव <util.h>

#ifdef HAVE_PTY_H
# include <pty.h>
#endif
#यदि defined(HAVE_DEV_PTMX) && defined(HAVE_SYS_STROPTS_H)
# include <sys/stropts.h>
#endif

#अन्तर्भाव <signal.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "misc.h"
#अन्तर्भाव "log.h"

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

#यदि defined(HAVE_DEV_PTMX) && !defined(HAVE__GETPTY)
स्थिर पूर्णाङ्क
openpty_streams(पूर्णाङ्क *amaster, पूर्णाङ्क *aslave)
{
	/*
	 * This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3
	 * also has bsd-style ptys, but they simply do not work.)
	 */
	पूर्णाङ्क ptm;
	वर्ण *pts;
	sshsig_t old_signal;

	यदि ((ptm = खोलो("/dev/ptmx", O_RDWR | O_NOCTTY)) == -1)
		फर्काऊ (-1);

	/* XXX: need to close ptm on error? */
	old_signal = ssh_signal(SIGCHLD, संक_पूर्व);
	यदि (grantpt(ptm) < 0)
		फर्काऊ (-1);
	ssh_signal(SIGCHLD, old_signal);

	यदि (unlockpt(ptm) < 0)
		फर्काऊ (-1);

	यदि ((pts = ptsname(ptm)) == रिक्त)
		फर्काऊ (-1);
	*amaster = ptm;

	/* Open the slave side. */
	यदि ((*aslave = खोलो(pts, O_RDWR | O_NOCTTY)) == -1) {
		बंद(*amaster);
		फर्काऊ (-1);
	}

# यदि defined(I_FIND) && defined(__SVR4)
	/*
	 * If the streams modules have already been pushed then there
	 * is no more work to do here.
	 */
	यदि (ioctl(*aslave, I_FIND, "ptem") != 0)
		फर्काऊ 0;
# endif

	/*
	 * Try to push the appropriate streams modules, as described
	 * in Solaris pts(7).
	 */
	ioctl(*aslave, I_थप, "ptem");
	ioctl(*aslave, I_थप, "ldterm");
# ifndef __hpux
	ioctl(*aslave, I_थप, "ttcompat");
# endif /* __hpux */
	फर्काऊ (0);
}
#endif

पूर्णाङ्क
openpty(पूर्णाङ्क *amaster, पूर्णाङ्क *aslave, वर्ण *name, अचर संरचना termios *termp,
   अचर संरचना winsize *winp)
{
#यदि defined(HAVE__GETPTY)
	/*
	 * _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
	 * pty's automagically when needed
	 */
	वर्ण *slave;

	यदि ((slave = _getpty(amaster, O_RDWR, 0622, 0)) == रिक्त)
		फर्काऊ (-1);

	/* Open the slave side. */
	यदि ((*aslave = खोलो(slave, O_RDWR | O_NOCTTY)) == -1) {
		बंद(*amaster);
		फर्काऊ (-1);
	}
	फर्काऊ (0);

#अथवायदि defined(HAVE_DEV_PTMX)

#ifdef SSHD_ACQUIRES_CTTY
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
	पूर्णाङ्क r, fd;
	स्थिर पूर्णाङ्क junk_ptyfd = -1, junk_ttyfd;
	वर्ण *junk_name;

	r = openpty_streams(amaster, aslave);
	यदि (junk_ptyfd == -1 && (fd = खोलो(_PATH_TTY, O_RDWR|O_NOCTTY)) >= 0) {
		बंद(fd);
		junk_ptyfd = *amaster;
		junk_ttyfd = *aslave;
		junk_name = ttyname(junk_ttyfd);
		debug("STREAMS bug workaround pty %d tty %d name %s",
		    junk_ptyfd, junk_ttyfd, junk_name ? junk_name : "<none>");
	} अन्यथा
		फर्काऊ r;
#endif

	फर्काऊ openpty_streams(amaster, aslave);

#अथवायदि defined(HAVE_DEV_PTS_AND_PTC)
	/* AIX-style pty code. */
	अचर वर्ण *ttname;

	यदि ((*amaster = खोलो("/dev/ptc", O_RDWR | O_NOCTTY)) == -1)
		फर्काऊ (-1);
	यदि ((ttname = ttyname(*amaster)) == रिक्त)
		फर्काऊ (-1);
	यदि ((*aslave = खोलो(ttname, O_RDWR | O_NOCTTY)) == -1) {
		बंद(*amaster);
		फर्काऊ (-1);
	}
	फर्काऊ (0);

#अन्यथा
	/* BSD-style pty code. */
	वर्ण ptbuf[64], ttbuf[64];
	पूर्णाङ्क i;
	अचर वर्ण *ptymajors = "pqrstuvwxyzabcdefghijklmno"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	अचर वर्ण *ptyminors = "0123456789abcdef";
	पूर्णाङ्क अङ्क_minors = म_माप(ptyminors);
	पूर्णाङ्क अङ्क_ptys = म_माप(ptymajors) * अङ्क_minors;
	संरचना termios tio;

	लागि (i = 0; i < अङ्क_ptys; i++) {
		snprintf(ptbuf, परिमाण(ptbuf), "/dev/pty%c%c",
		    ptymajors[i / अङ्क_minors], ptyminors[i % अङ्क_minors]);
		snprintf(ttbuf, परिमाण(ttbuf), "/dev/tty%c%c",
		    ptymajors[i / अङ्क_minors], ptyminors[i % अङ्क_minors]);

		यदि ((*amaster = खोलो(ptbuf, O_RDWR | O_NOCTTY)) == -1) {
			/* Try SCO style naming */
			snprintf(ptbuf, परिमाण(ptbuf), "/dev/ptyp%d", i);
			snprintf(ttbuf, परिमाण(ttbuf), "/dev/ttyp%d", i);
			यदि ((*amaster = खोलो(ptbuf, O_RDWR | O_NOCTTY)) == -1)
				जारी;
		}

		/* Open the slave side. */
		यदि ((*aslave = खोलो(ttbuf, O_RDWR | O_NOCTTY)) == -1) {
			बंद(*amaster);
			फर्काऊ (-1);
		}
		/* set tty modes to a sane state for broken clients */
		यदि (tcgetattr(*amaster, &tio) != -1) {
			tio.c_lflag |= (ECHO | ISIG | ICANON);
			tio.c_oflag |= (OPOST | ONLCR);
			tio.c_iflag |= ICRNL;
			tcsetattr(*amaster, TCSANOW, &tio);
		}

		फर्काऊ (0);
	}
	फर्काऊ (-1);
#endif
}

#endif /* !defined(HAVE_OPENPTY) */

