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

#অন্তর্ভাব "includes.h"
#যদি !defined(HAVE_OPENPTY)

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>

#অন্তর্ভাব <sys/stat.h>
#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#অন্তর্ভাব <util.h>

#ifdef HAVE_PTY_H
# include <pty.h>
#endif
#যদি defined(HAVE_DEV_PTMX) && defined(HAVE_SYS_STROPTS_H)
# include <sys/stropts.h>
#endif

#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "log.h"

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

#যদি defined(HAVE_DEV_PTMX) && !defined(HAVE__GETPTY)
স্থির পূর্ণাঙ্ক
openpty_streams(পূর্ণাঙ্ক *amaster, পূর্ণাঙ্ক *aslave)
{
	/*
	 * This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3
	 * also has bsd-style ptys, but they simply do not work.)
	 */
	পূর্ণাঙ্ক ptm;
	বর্ণ *pts;
	sshsig_t old_signal;

	যদি ((ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY)) == -1)
		প্রত্যাগম (-1);

	/* XXX: need to close ptm on error? */
	old_signal = ssh_signal(SIGCHLD, SIG_DFL);
	যদি (grantpt(ptm) < 0)
		প্রত্যাগম (-1);
	ssh_signal(SIGCHLD, old_signal);

	যদি (unlockpt(ptm) < 0)
		প্রত্যাগম (-1);

	যদি ((pts = ptsname(ptm)) == রিক্ত)
		প্রত্যাগম (-1);
	*amaster = ptm;

	/* Open the slave side. */
	যদি ((*aslave = open(pts, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		প্রত্যাগম (-1);
	}

# যদি defined(I_FIND) && defined(__SVR4)
	/*
	 * If the streams modules have already been pushed then there
	 * is no more work to do here.
	 */
	যদি (ioctl(*aslave, I_FIND, "ptem") != 0)
		প্রত্যাগম 0;
# endif

	/*
	 * Try to push the appropriate streams modules, as described
	 * in Solaris pts(7).
	 */
	ioctl(*aslave, I_ঠেলো, "ptem");
	ioctl(*aslave, I_ঠেলো, "ldterm");
# ifndef __hpux
	ioctl(*aslave, I_ঠেলো, "ttcompat");
# endif /* __hpux */
	প্রত্যাগম (0);
}
#endif

পূর্ণাঙ্ক
openpty(পূর্ণাঙ্ক *amaster, পূর্ণাঙ্ক *aslave, বর্ণ *name, ধ্রুব সংরচনা termios *termp,
   ধ্রুব সংরচনা winsize *winp)
{
#যদি defined(HAVE__GETPTY)
	/*
	 * _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
	 * pty's automagically when needed
	 */
	বর্ণ *slave;

	যদি ((slave = _getpty(amaster, O_RDWR, 0622, 0)) == রিক্ত)
		প্রত্যাগম (-1);

	/* Open the slave side. */
	যদি ((*aslave = open(slave, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		প্রত্যাগম (-1);
	}
	প্রত্যাগম (0);

#নোচেদ্যদি defined(HAVE_DEV_PTMX)

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
	পূর্ণাঙ্ক r, fd;
	স্থির পূর্ণাঙ্ক junk_ptyfd = -1, junk_ttyfd;
	বর্ণ *junk_name;

	r = openpty_streams(amaster, aslave);
	যদি (junk_ptyfd == -1 && (fd = open(_PATH_TTY, O_RDWR|O_NOCTTY)) >= 0) {
		close(fd);
		junk_ptyfd = *amaster;
		junk_ttyfd = *aslave;
		junk_name = ttyname(junk_ttyfd);
		debug("STREAMS bug workaround pty %d tty %d name %s",
		    junk_ptyfd, junk_ttyfd, junk_name ? junk_name : "<none>");
	} অন্যথা
		প্রত্যাগম r;
#endif

	প্রত্যাগম openpty_streams(amaster, aslave);

#নোচেদ্যদি defined(HAVE_DEV_PTS_AND_PTC)
	/* AIX-style pty code. */
	ধ্রুব বর্ণ *ttname;

	যদি ((*amaster = open("/dev/ptc", O_RDWR | O_NOCTTY)) == -1)
		প্রত্যাগম (-1);
	যদি ((ttname = ttyname(*amaster)) == রিক্ত)
		প্রত্যাগম (-1);
	যদি ((*aslave = open(ttname, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		প্রত্যাগম (-1);
	}
	প্রত্যাগম (0);

#অন্যথা
	/* BSD-style pty code. */
	বর্ণ ptbuf[64], ttbuf[64];
	পূর্ণাঙ্ক i;
	ধ্রুব বর্ণ *ptymajors = "pqrstuvwxyzabcdefghijklmno"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	ধ্রুব বর্ণ *ptyminors = "0123456789abcdef";
	পূর্ণাঙ্ক অঙ্ক_minors = strlen(ptyminors);
	পূর্ণাঙ্ক অঙ্ক_ptys = strlen(ptymajors) * অঙ্ক_minors;
	সংরচনা termios tio;

	প্রতি (i = 0; i < অঙ্ক_ptys; i++) {
		snprintf(ptbuf, পরিমাণ(ptbuf), "/dev/pty%c%c",
		    ptymajors[i / অঙ্ক_minors], ptyminors[i % অঙ্ক_minors]);
		snprintf(ttbuf, পরিমাণ(ttbuf), "/dev/tty%c%c",
		    ptymajors[i / অঙ্ক_minors], ptyminors[i % অঙ্ক_minors]);

		যদি ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1) {
			/* Try SCO style naming */
			snprintf(ptbuf, পরিমাণ(ptbuf), "/dev/ptyp%d", i);
			snprintf(ttbuf, পরিমাণ(ttbuf), "/dev/ttyp%d", i);
			যদি ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1)
				অনুবর্ত;
		}

		/* Open the slave side. */
		যদি ((*aslave = open(ttbuf, O_RDWR | O_NOCTTY)) == -1) {
			close(*amaster);
			প্রত্যাগম (-1);
		}
		/* set tty modes to a sane state for broken clients */
		যদি (tcgetattr(*amaster, &tio) != -1) {
			tio.c_lflag |= (ECHO | ISIG | ICANON);
			tio.c_oflag |= (OPOST | ONLCR);
			tio.c_iflag |= ICRNL;
			tcsetattr(*amaster, TCSANOW, &tio);
		}

		প্রত্যাগম (0);
	}
	প্রত্যাগম (-1);
#endif
}

#endif /* !defined(HAVE_OPENPTY) */

