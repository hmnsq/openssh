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

#అన్తర్భావ "includes.h"
#ఒకవేళ !defined(HAVE_OPENPTY)

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>

#అన్తర్భావ <sys/stat.h>
#నిర్వచితమైతే HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#అయితే_ముగింపు

#నిర్వచితమైతే HAVE_FCNTL_H
# include <fcntl.h>
#అయితే_ముగింపు

#అన్తర్భావ <util.h>

#నిర్వచితమైతే HAVE_PTY_H
# include <pty.h>
#అయితే_ముగింపు
#ఒకవేళ defined(HAVE_DEV_PTMX) && defined(HAVE_SYS_STROPTS_H)
# include <sys/stropts.h>
#అయితే_ముగింపు

#అన్తర్భావ <signal.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "misc.h"
#అన్తర్భావ "log.h"

#నిర్వచితం_కాకపోతే O_NOCTTY
#నిర్వచించు O_NOCTTY 0
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_DEV_PTMX) && !defined(HAVE__GETPTY)
స్థిర పూర్ణాంకం
openpty_streams(పూర్ణాంకం *amaster, పూర్ణాంకం *aslave)
{
	/*
	 * This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3
	 * also has bsd-style ptys, but they simply do not work.)
	 */
	పూర్ణాంకం ptm;
	అక్షరం *pts;
	sshsig_t old_signal;

	ఒకవేళ ((ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY)) == -1)
		తిరిగి (-1);

	/* XXX: need to close ptm on error? */
	old_signal = ssh_signal(SIGCHLD, SIG_DFL);
	ఒకవేళ (grantpt(ptm) < 0)
		తిరిగి (-1);
	ssh_signal(SIGCHLD, old_signal);

	ఒకవేళ (unlockpt(ptm) < 0)
		తిరిగి (-1);

	ఒకవేళ ((pts = ptsname(ptm)) == ఖాళీ)
		తిరిగి (-1);
	*amaster = ptm;

	/* Open the slave side. */
	ఒకవేళ ((*aslave = open(pts, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		తిరిగి (-1);
	}

# ఒకవేళ defined(I_కనుగొను) && defined(__SVR4)
	/*
	 * If the streams modules have already been pushed then there
	 * is no more work to do here.
	 */
	ఒకవేళ (ioctl(*aslave, I_కనుగొను, "ptem") != 0)
		తిరిగి 0;
# endif

	/*
	 * Try to push the appropriate streams modules, as described
	 * in Solaris pts(7).
	 */
	ioctl(*aslave, I_నెట్టు, "ptem");
	ioctl(*aslave, I_నెట్టు, "ldterm");
# ifndef __hpux
	ioctl(*aslave, I_నెట్టు, "ttcompat");
# endif /* __hpux */
	తిరిగి (0);
}
#అయితే_ముగింపు

పూర్ణాంకం
openpty(పూర్ణాంకం *amaster, పూర్ణాంకం *aslave, అక్షరం *name, స్థిరరాశి నిర్మాణం termios *termp,
   స్థిరరాశి నిర్మాణం winsize *winp)
{
#ఒకవేళ defined(HAVE__GETPTY)
	/*
	 * _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
	 * pty's automagically when needed
	 */
	అక్షరం *slave;

	ఒకవేళ ((slave = _getpty(amaster, O_RDWR, 0622, 0)) == ఖాళీ)
		తిరిగి (-1);

	/* Open the slave side. */
	ఒకవేళ ((*aslave = open(slave, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		తిరిగి (-1);
	}
	తిరిగి (0);

#లేదావేళ defined(HAVE_DEV_PTMX)

#నిర్వచితమైతే SSHD_ACQUIRES_CTTY
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
	పూర్ణాంకం r, fd;
	స్థిర పూర్ణాంకం junk_ptyfd = -1, junk_ttyfd;
	అక్షరం *junk_name;

	r = openpty_streams(amaster, aslave);
	ఒకవేళ (junk_ptyfd == -1 && (fd = open(_PATH_TTY, O_RDWR|O_NOCTTY)) >= 0) {
		close(fd);
		junk_ptyfd = *amaster;
		junk_ttyfd = *aslave;
		junk_name = ttyname(junk_ttyfd);
		debug("STREAMS bug workaround pty %d tty %d name %s",
		    junk_ptyfd, junk_ttyfd, junk_name ? junk_name : "<none>");
	} లేకపోతే
		తిరిగి r;
#అయితే_ముగింపు

	తిరిగి openpty_streams(amaster, aslave);

#లేదావేళ defined(HAVE_DEV_PTS_AND_PTC)
	/* AIX-style pty code. */
	స్థిరరాశి అక్షరం *ttname;

	ఒకవేళ ((*amaster = open("/dev/ptc", O_RDWR | O_NOCTTY)) == -1)
		తిరిగి (-1);
	ఒకవేళ ((ttname = ttyname(*amaster)) == ఖాళీ)
		తిరిగి (-1);
	ఒకవేళ ((*aslave = open(ttname, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		తిరిగి (-1);
	}
	తిరిగి (0);

#లేకపోతే
	/* BSD-style pty code. */
	అక్షరం ptbuf[64], ttbuf[64];
	పూర్ణాంకం i;
	స్థిరరాశి అక్షరం *ptymajors = "pqrstuvwxyzabcdefghijklmno"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	స్థిరరాశి అక్షరం *ptyminors = "0123456789abcdef";
	పూర్ణాంకం అంకె_minors = అక్షరశ్రేణి_పొడవు(ptyminors);
	పూర్ణాంకం అంకె_ptys = అక్షరశ్రేణి_పొడవు(ptymajors) * అంకె_minors;
	నిర్మాణం termios tio;

	కొరకు (i = 0; i < అంకె_ptys; i++) {
		snprintf(ptbuf, పరిమాణం(ptbuf), "/dev/pty%c%c",
		    ptymajors[i / అంకె_minors], ptyminors[i % అంకె_minors]);
		snprintf(ttbuf, పరిమాణం(ttbuf), "/dev/tty%c%c",
		    ptymajors[i / అంకె_minors], ptyminors[i % అంకె_minors]);

		ఒకవేళ ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1) {
			/* Try SCO style naming */
			snprintf(ptbuf, పరిమాణం(ptbuf), "/dev/ptyp%d", i);
			snprintf(ttbuf, పరిమాణం(ttbuf), "/dev/ttyp%d", i);
			ఒకవేళ ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1)
				కొనసాగు;
		}

		/* Open the slave side. */
		ఒకవేళ ((*aslave = open(ttbuf, O_RDWR | O_NOCTTY)) == -1) {
			close(*amaster);
			తిరిగి (-1);
		}
		/* set tty modes to a sane state for broken clients */
		ఒకవేళ (tcgetattr(*amaster, &tio) != -1) {
			tio.c_lflag |= (ECHO | ISIG | ICANON);
			tio.c_oflag |= (OPOST | ONLCR);
			tio.c_iflag |= ICRNL;
			tcsetattr(*amaster, TCSANOW, &tio);
		}

		తిరిగి (0);
	}
	తిరిగి (-1);
#అయితే_ముగింపు
}

#అయితే_ముగింపు /* !defined(HAVE_OPENPTY) */

