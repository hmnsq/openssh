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

#અન્તર્ભાવ "includes.h"
#જો !defined(HAVE_OPENPTY)

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>

#અન્તર્ભાવ <sys/stat.h>
#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#અન્તર્ભાવ <util.h>

#ifdef HAVE_PTY_H
# include <pty.h>
#endif
#જો defined(HAVE_DEV_PTMX) && defined(HAVE_SYS_STROPTS_H)
# include <sys/stropts.h>
#endif

#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "log.h"

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

#જો defined(HAVE_DEV_PTMX) && !defined(HAVE__GETPTY)
સ્થિર પૂર્ણાંક
openpty_streams(પૂર્ણાંક *amaster, પૂર્ણાંક *aslave)
{
	/*
	 * This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3
	 * also has bsd-style ptys, but they simply do not work.)
	 */
	પૂર્ણાંક ptm;
	અક્ષર *pts;
	sshsig_t old_signal;

	જો ((ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY)) == -1)
		પાછા (-1);

	/* XXX: need to close ptm on error? */
	old_signal = ssh_signal(SIGCHLD, SIG_DFL);
	જો (grantpt(ptm) < 0)
		પાછા (-1);
	ssh_signal(SIGCHLD, old_signal);

	જો (unlockpt(ptm) < 0)
		પાછા (-1);

	જો ((pts = ptsname(ptm)) == ખાલી)
		પાછા (-1);
	*amaster = ptm;

	/* Open the slave side. */
	જો ((*aslave = open(pts, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		પાછા (-1);
	}

# જો defined(I_FIND) && defined(__SVR4)
	/*
	 * If the streams modules have already been pushed then there
	 * is no more work to do here.
	 */
	જો (ioctl(*aslave, I_FIND, "ptem") != 0)
		પાછા 0;
# endif

	/*
	 * Try to push the appropriate streams modules, as described
	 * in Solaris pts(7).
	 */
	ioctl(*aslave, I_ધકેલો, "ptem");
	ioctl(*aslave, I_ધકેલો, "ldterm");
# ifndef __hpux
	ioctl(*aslave, I_ધકેલો, "ttcompat");
# endif /* __hpux */
	પાછા (0);
}
#endif

પૂર્ણાંક
openpty(પૂર્ણાંક *amaster, પૂર્ણાંક *aslave, અક્ષર *name, અચલ સંરચના termios *termp,
   અચલ સંરચના winsize *winp)
{
#જો defined(HAVE__GETPTY)
	/*
	 * _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
	 * pty's automagically when needed
	 */
	અક્ષર *slave;

	જો ((slave = _getpty(amaster, O_RDWR, 0622, 0)) == ખાલી)
		પાછા (-1);

	/* Open the slave side. */
	જો ((*aslave = open(slave, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		પાછા (-1);
	}
	પાછા (0);

#અથવાજો defined(HAVE_DEV_PTMX)

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
	પૂર્ણાંક r, fd;
	સ્થિર પૂર્ણાંક junk_ptyfd = -1, junk_ttyfd;
	અક્ષર *junk_name;

	r = openpty_streams(amaster, aslave);
	જો (junk_ptyfd == -1 && (fd = open(_PATH_TTY, O_RDWR|O_NOCTTY)) >= 0) {
		close(fd);
		junk_ptyfd = *amaster;
		junk_ttyfd = *aslave;
		junk_name = ttyname(junk_ttyfd);
		debug("STREAMS bug workaround pty %d tty %d name %s",
		    junk_ptyfd, junk_ttyfd, junk_name ? junk_name : "<none>");
	} નહીંતર
		પાછા r;
#endif

	પાછા openpty_streams(amaster, aslave);

#અથવાજો defined(HAVE_DEV_PTS_AND_PTC)
	/* AIX-style pty code. */
	અચલ અક્ષર *ttname;

	જો ((*amaster = open("/dev/ptc", O_RDWR | O_NOCTTY)) == -1)
		પાછા (-1);
	જો ((ttname = ttyname(*amaster)) == ખાલી)
		પાછા (-1);
	જો ((*aslave = open(ttname, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		પાછા (-1);
	}
	પાછા (0);

#નહીંતર
	/* BSD-style pty code. */
	અક્ષર ptbuf[64], ttbuf[64];
	પૂર્ણાંક i;
	અચલ અક્ષર *ptymajors = "pqrstuvwxyzabcdefghijklmno"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	અચલ અક્ષર *ptyminors = "0123456789abcdef";
	પૂર્ણાંક અંક_minors = strlen(ptyminors);
	પૂર્ણાંક અંક_ptys = strlen(ptymajors) * અંક_minors;
	સંરચના termios tio;

	માટે (i = 0; i < અંક_ptys; i++) {
		snprintf(ptbuf, કદ(ptbuf), "/dev/pty%c%c",
		    ptymajors[i / અંક_minors], ptyminors[i % અંક_minors]);
		snprintf(ttbuf, કદ(ttbuf), "/dev/tty%c%c",
		    ptymajors[i / અંક_minors], ptyminors[i % અંક_minors]);

		જો ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1) {
			/* Try SCO style naming */
			snprintf(ptbuf, કદ(ptbuf), "/dev/ptyp%d", i);
			snprintf(ttbuf, કદ(ttbuf), "/dev/ttyp%d", i);
			જો ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1)
				ચાલુ;
		}

		/* Open the slave side. */
		જો ((*aslave = open(ttbuf, O_RDWR | O_NOCTTY)) == -1) {
			close(*amaster);
			પાછા (-1);
		}
		/* set tty modes to a sane state for broken clients */
		જો (tcgetattr(*amaster, &tio) != -1) {
			tio.c_lflag |= (ECHO | ISIG | ICANON);
			tio.c_oflag |= (OPOST | ONLCR);
			tio.c_iflag |= ICRNL;
			tcsetattr(*amaster, TCSANOW, &tio);
		}

		પાછા (0);
	}
	પાછા (-1);
#endif
}

#endif /* !defined(HAVE_OPENPTY) */

