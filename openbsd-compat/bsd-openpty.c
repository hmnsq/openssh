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

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ଯଦି !defined(HAVE_OPENPTY)

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>

#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ଅନ୍ତର୍ଭାଵ <util.h>

#ifdef HAVE_PTY_H
# include <pty.h>
#endif
#ଯଦି defined(HAVE_DEV_PTMX) && defined(HAVE_SYS_STROPTS_H)
# include <sys/stropts.h>
#endif

#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

#ଯଦି defined(HAVE_DEV_PTMX) && !defined(HAVE__GETPTY)
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
openpty_streams(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *amaster, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *aslave)
{
	/*
	 * This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3
	 * also has bsd-style ptys, but they simply do not work.)
	 */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ptm;
	ଅକ୍ଷର *pts;
	sshsig_t old_signal;

	ଯଦି ((ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY)) == -1)
		ଫେରନ୍ତୁ (-1);

	/* XXX: need to close ptm on error? */
	old_signal = ssh_signal(SIGCHLD, SIG_DFL);
	ଯଦି (grantpt(ptm) < 0)
		ଫେରନ୍ତୁ (-1);
	ssh_signal(SIGCHLD, old_signal);

	ଯଦି (unlockpt(ptm) < 0)
		ଫେରନ୍ତୁ (-1);

	ଯଦି ((pts = ptsname(ptm)) == ଖାଲି)
		ଫେରନ୍ତୁ (-1);
	*amaster = ptm;

	/* Open the slave side. */
	ଯଦି ((*aslave = open(pts, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		ଫେରନ୍ତୁ (-1);
	}

# ଯଦି defined(I_FIND) && defined(__SVR4)
	/*
	 * If the streams modules have already been pushed then there
	 * is no more work to do here.
	 */
	ଯଦି (ioctl(*aslave, I_FIND, "ptem") != 0)
		ଫେରନ୍ତୁ 0;
# endif

	/*
	 * Try to push the appropriate streams modules, as described
	 * in Solaris pts(7).
	 */
	ioctl(*aslave, I_ଠେଲ, "ptem");
	ioctl(*aslave, I_ଠେଲ, "ldterm");
# ifndef __hpux
	ioctl(*aslave, I_ଠେଲ, "ttcompat");
# endif /* __hpux */
	ଫେରନ୍ତୁ (0);
}
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
openpty(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *amaster, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *aslave, ଅକ୍ଷର *name, ଅଚଳ ସଂରଚନା termios *termp,
   ଅଚଳ ସଂରଚନା winsize *winp)
{
#ଯଦି defined(HAVE__GETPTY)
	/*
	 * _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
	 * pty's automagically when needed
	 */
	ଅକ୍ଷର *slave;

	ଯଦି ((slave = _getpty(amaster, O_RDWR, 0622, 0)) == ଖାଲି)
		ଫେରନ୍ତୁ (-1);

	/* Open the slave side. */
	ଯଦି ((*aslave = open(slave, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		ଫେରନ୍ତୁ (-1);
	}
	ଫେରନ୍ତୁ (0);

#ନଚେତଯଦି defined(HAVE_DEV_PTMX)

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
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, fd;
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା junk_ptyfd = -1, junk_ttyfd;
	ଅକ୍ଷର *junk_name;

	r = openpty_streams(amaster, aslave);
	ଯଦି (junk_ptyfd == -1 && (fd = open(_PATH_TTY, O_RDWR|O_NOCTTY)) >= 0) {
		close(fd);
		junk_ptyfd = *amaster;
		junk_ttyfd = *aslave;
		junk_name = ttyname(junk_ttyfd);
		debug("STREAMS bug workaround pty %d tty %d name %s",
		    junk_ptyfd, junk_ttyfd, junk_name ? junk_name : "<none>");
	} ଅନ୍ୟଥା
		ଫେରନ୍ତୁ r;
#endif

	ଫେରନ୍ତୁ openpty_streams(amaster, aslave);

#ନଚେତଯଦି defined(HAVE_DEV_PTS_AND_PTC)
	/* AIX-style pty code. */
	ଅଚଳ ଅକ୍ଷର *ttname;

	ଯଦି ((*amaster = open("/dev/ptc", O_RDWR | O_NOCTTY)) == -1)
		ଫେରନ୍ତୁ (-1);
	ଯଦି ((ttname = ttyname(*amaster)) == ଖାଲି)
		ଫେରନ୍ତୁ (-1);
	ଯଦି ((*aslave = open(ttname, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		ଫେରନ୍ତୁ (-1);
	}
	ଫେରନ୍ତୁ (0);

#ଅନ୍ୟଥା
	/* BSD-style pty code. */
	ଅକ୍ଷର ptbuf[64], ttbuf[64];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ଅଚଳ ଅକ୍ଷର *ptymajors = "pqrstuvwxyzabcdefghijklmno"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	ଅଚଳ ଅକ୍ଷର *ptyminors = "0123456789abcdef";
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଅଙ୍କ_minors = strlen(ptyminors);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଅଙ୍କ_ptys = strlen(ptymajors) * ଅଙ୍କ_minors;
	ସଂରଚନା termios tio;

	ପାଇଁ (i = 0; i < ଅଙ୍କ_ptys; i++) {
		snprintf(ptbuf, ଆକାର(ptbuf), "/dev/pty%c%c",
		    ptymajors[i / ଅଙ୍କ_minors], ptyminors[i % ଅଙ୍କ_minors]);
		snprintf(ttbuf, ଆକାର(ttbuf), "/dev/tty%c%c",
		    ptymajors[i / ଅଙ୍କ_minors], ptyminors[i % ଅଙ୍କ_minors]);

		ଯଦି ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1) {
			/* Try SCO style naming */
			snprintf(ptbuf, ଆକାର(ptbuf), "/dev/ptyp%d", i);
			snprintf(ttbuf, ଆକାର(ttbuf), "/dev/ttyp%d", i);
			ଯଦି ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1)
				ଜାରି;
		}

		/* Open the slave side. */
		ଯଦି ((*aslave = open(ttbuf, O_RDWR | O_NOCTTY)) == -1) {
			close(*amaster);
			ଫେରନ୍ତୁ (-1);
		}
		/* set tty modes to a sane state for broken clients */
		ଯଦି (tcgetattr(*amaster, &tio) != -1) {
			tio.c_lflag |= (ECHO | ISIG | ICANON);
			tio.c_oflag |= (OPOST | ONLCR);
			tio.c_iflag |= ICRNL;
			tcsetattr(*amaster, TCSANOW, &tio);
		}

		ଫେରନ୍ତୁ (0);
	}
	ଫେରନ୍ତୁ (-1);
#endif
}

#endif /* !defined(HAVE_OPENPTY) */

