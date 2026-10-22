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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ಯದಿ !defined(HAVE_OPENPTY)

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ಅನ್ತರ್ಭಾವ <util.h>

#ifdef HAVE_PTY_H
# include <pty.h>
#endif
#ಯದಿ defined(HAVE_DEV_PTMX) && defined(HAVE_SYS_STROPTS_H)
# include <sys/stropts.h>
#endif

#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

#ಯದಿ defined(HAVE_DEV_PTMX) && !defined(HAVE__GETPTY)
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
openpty_streams(ಪೂರ್ಣಾಙ್ಕ *amaster, ಪೂರ್ಣಾಙ್ಕ *aslave)
{
	/*
	 * This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3
	 * also has bsd-style ptys, but they simply do not work.)
	 */
	ಪೂರ್ಣಾಙ್ಕ ptm;
	ವರ್ಣ *pts;
	sshsig_t old_signal;

	ಯದಿ ((ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY)) == -1)
		ಪ್ರತ್ಯಾಗಮ (-1);

	/* XXX: need to close ptm on error? */
	old_signal = ssh_signal(SIGCHLD, SIG_DFL);
	ಯದಿ (grantpt(ptm) < 0)
		ಪ್ರತ್ಯಾಗಮ (-1);
	ssh_signal(SIGCHLD, old_signal);

	ಯದಿ (unlockpt(ptm) < 0)
		ಪ್ರತ್ಯಾಗಮ (-1);

	ಯದಿ ((pts = ptsname(ptm)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (-1);
	*amaster = ptm;

	/* Open the slave side. */
	ಯದಿ ((*aslave = open(pts, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

# ಯದಿ defined(I_FIND) && defined(__SVR4)
	/*
	 * If the streams modules have already been pushed then there
	 * is no more work to do here.
	 */
	ಯದಿ (ioctl(*aslave, I_FIND, "ptem") != 0)
		ಪ್ರತ್ಯಾಗಮ 0;
# endif

	/*
	 * Try to push the appropriate streams modules, as described
	 * in Solaris pts(7).
	 */
	ioctl(*aslave, I_ತಳ್ಳು, "ptem");
	ioctl(*aslave, I_ತಳ್ಳು, "ldterm");
# ifndef __hpux
	ioctl(*aslave, I_ತಳ್ಳು, "ttcompat");
# endif /* __hpux */
	ಪ್ರತ್ಯಾಗಮ (0);
}
#endif

ಪೂರ್ಣಾಙ್ಕ
openpty(ಪೂರ್ಣಾಙ್ಕ *amaster, ಪೂರ್ಣಾಙ್ಕ *aslave, ವರ್ಣ *name, ಧ್ರುವ ಸಂರಚನಾ termios *termp,
   ಧ್ರುವ ಸಂರಚನಾ winsize *winp)
{
#ಯದಿ defined(HAVE__GETPTY)
	/*
	 * _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
	 * pty's automagically when needed
	 */
	ವರ್ಣ *slave;

	ಯದಿ ((slave = _getpty(amaster, O_RDWR, 0622, 0)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (-1);

	/* Open the slave side. */
	ಯದಿ ((*aslave = open(slave, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಪ್ರತ್ಯಾಗಮ (0);

#ನೋಚೇದ್ಯದಿ defined(HAVE_DEV_PTMX)

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
	ಪೂರ್ಣಾಙ್ಕ r, fd;
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ junk_ptyfd = -1, junk_ttyfd;
	ವರ್ಣ *junk_name;

	r = openpty_streams(amaster, aslave);
	ಯದಿ (junk_ptyfd == -1 && (fd = open(_PATH_TTY, O_RDWR|O_NOCTTY)) >= 0) {
		close(fd);
		junk_ptyfd = *amaster;
		junk_ttyfd = *aslave;
		junk_name = ttyname(junk_ttyfd);
		debug("STREAMS bug workaround pty %d tty %d name %s",
		    junk_ptyfd, junk_ttyfd, junk_name ? junk_name : "<none>");
	} ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ r;
#endif

	ಪ್ರತ್ಯಾಗಮ openpty_streams(amaster, aslave);

#ನೋಚೇದ್ಯದಿ defined(HAVE_DEV_PTS_AND_PTC)
	/* AIX-style pty code. */
	ಧ್ರುವ ವರ್ಣ *ttname;

	ಯದಿ ((*amaster = open("/dev/ptc", O_RDWR | O_NOCTTY)) == -1)
		ಪ್ರತ್ಯಾಗಮ (-1);
	ಯದಿ ((ttname = ttyname(*amaster)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (-1);
	ಯದಿ ((*aslave = open(ttname, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಪ್ರತ್ಯಾಗಮ (0);

#ಅನ್ಯಥಾ
	/* BSD-style pty code. */
	ವರ್ಣ ptbuf[64], ttbuf[64];
	ಪೂರ್ಣಾಙ್ಕ i;
	ಧ್ರುವ ವರ್ಣ *ptymajors = "pqrstuvwxyzabcdefghijklmno"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	ಧ್ರುವ ವರ್ಣ *ptyminors = "0123456789abcdef";
	ಪೂರ್ಣಾಙ್ಕ ಅಂಕೆ_minors = strlen(ptyminors);
	ಪೂರ್ಣಾಙ್ಕ ಅಂಕೆ_ptys = strlen(ptymajors) * ಅಂಕೆ_minors;
	ಸಂರಚನಾ termios tio;

	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_ptys; i++) {
		snprintf(ptbuf, ಪರಿಮಾಣ(ptbuf), "/dev/pty%c%c",
		    ptymajors[i / ಅಂಕೆ_minors], ptyminors[i % ಅಂಕೆ_minors]);
		snprintf(ttbuf, ಪರಿಮಾಣ(ttbuf), "/dev/tty%c%c",
		    ptymajors[i / ಅಂಕೆ_minors], ptyminors[i % ಅಂಕೆ_minors]);

		ಯದಿ ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1) {
			/* Try SCO style naming */
			snprintf(ptbuf, ಪರಿಮಾಣ(ptbuf), "/dev/ptyp%d", i);
			snprintf(ttbuf, ಪರಿಮಾಣ(ttbuf), "/dev/ttyp%d", i);
			ಯದಿ ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1)
				ಅನುವರ್ತ;
		}

		/* Open the slave side. */
		ಯದಿ ((*aslave = open(ttbuf, O_RDWR | O_NOCTTY)) == -1) {
			close(*amaster);
			ಪ್ರತ್ಯಾಗಮ (-1);
		}
		/* set tty modes to a sane state for broken clients */
		ಯದಿ (tcgetattr(*amaster, &tio) != -1) {
			tio.c_lflag |= (ECHO | ISIG | ICANON);
			tio.c_oflag |= (OPOST | ONLCR);
			tio.c_iflag |= ICRNL;
			tcsetattr(*amaster, TCSANOW, &tio);
		}

		ಪ್ರತ್ಯಾಗಮ (0);
	}
	ಪ್ರತ್ಯಾಗಮ (-1);
#endif
}

#endif /* !defined(HAVE_OPENPTY) */

