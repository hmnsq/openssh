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
#ಆದರೆ !defined(HAVE_OPENPTY)

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FCNTL_H
# include <fcntl.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ <util.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_PTY_H
# include <pty.h>
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(HAVE_DEV_PTMX) && defined(HAVE_SYS_STROPTS_H)
# include <sys/stropts.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ O_NOCTTY
#ವ್ಯಾಖ್ಯಾನಿಸು O_NOCTTY 0
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_DEV_PTMX) && !defined(HAVE__GETPTY)
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
openpty_streams(ಪೂರ್ಣಾಂಕ *amaster, ಪೂರ್ಣಾಂಕ *aslave)
{
	/*
	 * This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3
	 * also has bsd-style ptys, but they simply do not work.)
	 */
	ಪೂರ್ಣಾಂಕ ptm;
	ಅಕ್ಷರ *pts;
	sshsig_t old_signal;

	ಆದರೆ ((ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY)) == -1)
		ಹಿಂತಿರುಗಿ (-1);

	/* XXX: need to close ptm on error? */
	old_signal = ssh_signal(SIGCHLD, SIG_DFL);
	ಆದರೆ (grantpt(ptm) < 0)
		ಹಿಂತಿರುಗಿ (-1);
	ssh_signal(SIGCHLD, old_signal);

	ಆದರೆ (unlockpt(ptm) < 0)
		ಹಿಂತಿರುಗಿ (-1);

	ಆದರೆ ((pts = ptsname(ptm)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (-1);
	*amaster = ptm;

	/* Open the slave side. */
	ಆದರೆ ((*aslave = open(pts, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		ಹಿಂತಿರುಗಿ (-1);
	}

# ಆದರೆ defined(I_ಕಂಡುಹಿಡಿ) && defined(__SVR4)
	/*
	 * If the streams modules have already been pushed then there
	 * is no more work to do here.
	 */
	ಆದರೆ (ioctl(*aslave, I_ಕಂಡುಹಿಡಿ, "ptem") != 0)
		ಹಿಂತಿರುಗಿ 0;
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
	ಹಿಂತಿರುಗಿ (0);
}
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
openpty(ಪೂರ್ಣಾಂಕ *amaster, ಪೂರ್ಣಾಂಕ *aslave, ಅಕ್ಷರ *name, ಸ್ಥಿರಾಂಕ ರಚನೆ termios *termp,
   ಸ್ಥಿರಾಂಕ ರಚನೆ winsize *winp)
{
#ಆದರೆ defined(HAVE__GETPTY)
	/*
	 * _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
	 * pty's automagically when needed
	 */
	ಅಕ್ಷರ *slave;

	ಆದರೆ ((slave = _getpty(amaster, O_RDWR, 0622, 0)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (-1);

	/* Open the slave side. */
	ಆದರೆ ((*aslave = open(slave, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಹಿಂತಿರುಗಿ (0);

#ಅಥವಾಆದರೆ defined(HAVE_DEV_PTMX)

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSHD_ACQUIRES_CTTY
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
	ಪೂರ್ಣಾಂಕ r, fd;
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ junk_ptyfd = -1, junk_ttyfd;
	ಅಕ್ಷರ *junk_name;

	r = openpty_streams(amaster, aslave);
	ಆದರೆ (junk_ptyfd == -1 && (fd = open(_PATH_TTY, O_RDWR|O_NOCTTY)) >= 0) {
		close(fd);
		junk_ptyfd = *amaster;
		junk_ttyfd = *aslave;
		junk_name = ttyname(junk_ttyfd);
		debug("STREAMS bug workaround pty %d tty %d name %s",
		    junk_ptyfd, junk_ttyfd, junk_name ? junk_name : "<none>");
	} ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ r;
#ಆದರೆ_ಅಂತ್ಯ

	ಹಿಂತಿರುಗಿ openpty_streams(amaster, aslave);

#ಅಥವಾಆದರೆ defined(HAVE_DEV_PTS_AND_PTC)
	/* AIX-style pty code. */
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ttname;

	ಆದರೆ ((*amaster = open("/dev/ptc", O_RDWR | O_NOCTTY)) == -1)
		ಹಿಂತಿರುಗಿ (-1);
	ಆದರೆ ((ttname = ttyname(*amaster)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (-1);
	ಆದರೆ ((*aslave = open(ttname, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಹಿಂತಿರುಗಿ (0);

#ಇಲ್ಲದಿದ್ದರೆ
	/* BSD-style pty code. */
	ಅಕ್ಷರ ptbuf[64], ttbuf[64];
	ಪೂರ್ಣಾಂಕ i;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ptymajors = "pqrstuvwxyzabcdefghijklmno"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ptyminors = "0123456789abcdef";
	ಪೂರ್ಣಾಂಕ ಅಂಕೆ_minors = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ptyminors);
	ಪೂರ್ಣಾಂಕ ಅಂಕೆ_ptys = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ptymajors) * ಅಂಕೆ_minors;
	ರಚನೆ termios tio;

	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_ptys; i++) {
		snprintf(ptbuf, ಗಾತ್ರ(ptbuf), "/dev/pty%c%c",
		    ptymajors[i / ಅಂಕೆ_minors], ptyminors[i % ಅಂಕೆ_minors]);
		snprintf(ttbuf, ಗಾತ್ರ(ttbuf), "/dev/tty%c%c",
		    ptymajors[i / ಅಂಕೆ_minors], ptyminors[i % ಅಂಕೆ_minors]);

		ಆದರೆ ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1) {
			/* Try SCO style naming */
			snprintf(ptbuf, ಗಾತ್ರ(ptbuf), "/dev/ptyp%d", i);
			snprintf(ttbuf, ಗಾತ್ರ(ttbuf), "/dev/ttyp%d", i);
			ಆದರೆ ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1)
				ಮುಂದುವರಿ;
		}

		/* Open the slave side. */
		ಆದರೆ ((*aslave = open(ttbuf, O_RDWR | O_NOCTTY)) == -1) {
			close(*amaster);
			ಹಿಂತಿರುಗಿ (-1);
		}
		/* set tty modes to a sane state for broken clients */
		ಆದರೆ (tcgetattr(*amaster, &tio) != -1) {
			tio.c_lflag |= (ECHO | ISIG | ICANON);
			tio.c_oflag |= (OPOST | ONLCR);
			tio.c_iflag |= ICRNL;
			tcsetattr(*amaster, TCSANOW, &tio);
		}

		ಹಿಂತಿರುಗಿ (0);
	}
	ಹಿಂತಿರುಗಿ (-1);
#ಆದರೆ_ಅಂತ್ಯ
}

#ಆದರೆ_ಅಂತ್ಯ /* !defined(HAVE_OPENPTY) */

