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

#അന്തര്ഭാവ "includes.h"
#എങ്കിൽ !defined(HAVE_OPENPTY)

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>

#അന്തര്ഭാവ <sys/stat.h>
#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#അന്തര്ഭാവ <util.h>

#ifdef HAVE_PTY_H
# include <pty.h>
#endif
#എങ്കിൽ defined(HAVE_DEV_PTMX) && defined(HAVE_SYS_STROPTS_H)
# include <sys/stropts.h>
#endif

#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "log.h"

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

#എങ്കിൽ defined(HAVE_DEV_PTMX) && !defined(HAVE__GETPTY)
സ്ഥിതം പൂർണ്ണസംഖ്യ
openpty_streams(പൂർണ്ണസംഖ്യ *amaster, പൂർണ്ണസംഖ്യ *aslave)
{
	/*
	 * This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3
	 * also has bsd-style ptys, but they simply do not work.)
	 */
	പൂർണ്ണസംഖ്യ ptm;
	അക്ഷരം *pts;
	sshsig_t old_signal;

	എങ്കിൽ ((ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY)) == -1)
		തിരികെ (-1);

	/* XXX: need to close ptm on error? */
	old_signal = ssh_signal(SIGCHLD, SIG_DFL);
	എങ്കിൽ (grantpt(ptm) < 0)
		തിരികെ (-1);
	ssh_signal(SIGCHLD, old_signal);

	എങ്കിൽ (unlockpt(ptm) < 0)
		തിരികെ (-1);

	എങ്കിൽ ((pts = ptsname(ptm)) == ശൂന്യ)
		തിരികെ (-1);
	*amaster = ptm;

	/* Open the slave side. */
	എങ്കിൽ ((*aslave = open(pts, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		തിരികെ (-1);
	}

# എങ്കിൽ defined(I_FIND) && defined(__SVR4)
	/*
	 * If the streams modules have already been pushed then there
	 * is no more work to do here.
	 */
	എങ്കിൽ (ioctl(*aslave, I_FIND, "ptem") != 0)
		തിരികെ 0;
# endif

	/*
	 * Try to push the appropriate streams modules, as described
	 * in Solaris pts(7).
	 */
	ioctl(*aslave, I_തള്ളുക, "ptem");
	ioctl(*aslave, I_തള്ളുക, "ldterm");
# ifndef __hpux
	ioctl(*aslave, I_തള്ളുക, "ttcompat");
# endif /* __hpux */
	തിരികെ (0);
}
#endif

പൂർണ്ണസംഖ്യ
openpty(പൂർണ്ണസംഖ്യ *amaster, പൂർണ്ണസംഖ്യ *aslave, അക്ഷരം *name, സ്ഥിരം ഘടന termios *termp,
   സ്ഥിരം ഘടന winsize *winp)
{
#എങ്കിൽ defined(HAVE__GETPTY)
	/*
	 * _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
	 * pty's automagically when needed
	 */
	അക്ഷരം *slave;

	എങ്കിൽ ((slave = _getpty(amaster, O_RDWR, 0622, 0)) == ശൂന്യ)
		തിരികെ (-1);

	/* Open the slave side. */
	എങ്കിൽ ((*aslave = open(slave, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		തിരികെ (-1);
	}
	തിരികെ (0);

#അല്ലെങ്കിലെങ്കിൽ defined(HAVE_DEV_PTMX)

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
	പൂർണ്ണസംഖ്യ r, fd;
	സ്ഥിതം പൂർണ്ണസംഖ്യ junk_ptyfd = -1, junk_ttyfd;
	അക്ഷരം *junk_name;

	r = openpty_streams(amaster, aslave);
	എങ്കിൽ (junk_ptyfd == -1 && (fd = open(_PATH_TTY, O_RDWR|O_NOCTTY)) >= 0) {
		close(fd);
		junk_ptyfd = *amaster;
		junk_ttyfd = *aslave;
		junk_name = ttyname(junk_ttyfd);
		debug("STREAMS bug workaround pty %d tty %d name %s",
		    junk_ptyfd, junk_ttyfd, junk_name ? junk_name : "<none>");
	} അല്ലെങ്കിൽ
		തിരികെ r;
#endif

	തിരികെ openpty_streams(amaster, aslave);

#അല്ലെങ്കിലെങ്കിൽ defined(HAVE_DEV_PTS_AND_PTC)
	/* AIX-style pty code. */
	സ്ഥിരം അക്ഷരം *ttname;

	എങ്കിൽ ((*amaster = open("/dev/ptc", O_RDWR | O_NOCTTY)) == -1)
		തിരികെ (-1);
	എങ്കിൽ ((ttname = ttyname(*amaster)) == ശൂന്യ)
		തിരികെ (-1);
	എങ്കിൽ ((*aslave = open(ttname, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		തിരികെ (-1);
	}
	തിരികെ (0);

#അല്ലെങ്കിൽ
	/* BSD-style pty code. */
	അക്ഷരം ptbuf[64], ttbuf[64];
	പൂർണ്ണസംഖ്യ i;
	സ്ഥിരം അക്ഷരം *ptymajors = "pqrstuvwxyzabcdefghijklmno"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	സ്ഥിരം അക്ഷരം *ptyminors = "0123456789abcdef";
	പൂർണ്ണസംഖ്യ അക്കം_minors = strlen(ptyminors);
	പൂർണ്ണസംഖ്യ അക്കം_ptys = strlen(ptymajors) * അക്കം_minors;
	ഘടന termios tio;

	വേണ്ടി (i = 0; i < അക്കം_ptys; i++) {
		snprintf(ptbuf, വലുപ്പം(ptbuf), "/dev/pty%c%c",
		    ptymajors[i / അക്കം_minors], ptyminors[i % അക്കം_minors]);
		snprintf(ttbuf, വലുപ്പം(ttbuf), "/dev/tty%c%c",
		    ptymajors[i / അക്കം_minors], ptyminors[i % അക്കം_minors]);

		എങ്കിൽ ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1) {
			/* Try SCO style naming */
			snprintf(ptbuf, വലുപ്പം(ptbuf), "/dev/ptyp%d", i);
			snprintf(ttbuf, വലുപ്പം(ttbuf), "/dev/ttyp%d", i);
			എങ്കിൽ ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1)
				തുടരുക;
		}

		/* Open the slave side. */
		എങ്കിൽ ((*aslave = open(ttbuf, O_RDWR | O_NOCTTY)) == -1) {
			close(*amaster);
			തിരികെ (-1);
		}
		/* set tty modes to a sane state for broken clients */
		എങ്കിൽ (tcgetattr(*amaster, &tio) != -1) {
			tio.c_lflag |= (ECHO | ISIG | ICANON);
			tio.c_oflag |= (OPOST | ONLCR);
			tio.c_iflag |= ICRNL;
			tcsetattr(*amaster, TCSANOW, &tio);
		}

		തിരികെ (0);
	}
	തിരികെ (-1);
#endif
}

#endif /* !defined(HAVE_OPENPTY) */

