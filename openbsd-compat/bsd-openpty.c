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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਜੇ !defined(HAVE_OPENPTY)

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_FCNTL_H
# include <fcntl.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <util.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_PTY_H
# include <pty.h>
#ਜੇ_ਅੰਤ
#ਜੇ defined(HAVE_DEV_PTMX) && defined(HAVE_SYS_STROPTS_H)
# include <sys/stropts.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ O_NOCTTY
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ O_NOCTTY 0
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_DEV_PTMX) && !defined(HAVE__GETPTY)
ਸਥਿਰ ਪੂਰਨ
openpty_streams(ਪੂਰਨ *amaster, ਪੂਰਨ *aslave)
{
	/*
	 * This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3
	 * also has bsd-style ptys, but they simply do not work.)
	 */
	ਪੂਰਨ ptm;
	ਅੱਖਰ *pts;
	sshsig_t old_signal;

	ਜੇ ((ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY)) == -1)
		ਵਾਪਸ (-1);

	/* XXX: need to close ptm on error? */
	old_signal = ssh_signal(SIGCHLD, SIG_DFL);
	ਜੇ (grantpt(ptm) < 0)
		ਵਾਪਸ (-1);
	ssh_signal(SIGCHLD, old_signal);

	ਜੇ (unlockpt(ptm) < 0)
		ਵਾਪਸ (-1);

	ਜੇ ((pts = ptsname(ptm)) == ਨਿਰਾ)
		ਵਾਪਸ (-1);
	*amaster = ptm;

	/* Open the slave side. */
	ਜੇ ((*aslave = open(pts, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		ਵਾਪਸ (-1);
	}

# ਜੇ defined(I_ਲੱਭੋ) && defined(__SVR4)
	/*
	 * If the streams modules have already been pushed then there
	 * is no more work to do here.
	 */
	ਜੇ (ioctl(*aslave, I_ਲੱਭੋ, "ptem") != 0)
		ਵਾਪਸ 0;
# endif

	/*
	 * Try to push the appropriate streams modules, as described
	 * in Solaris pts(7).
	 */
	ioctl(*aslave, I_ਧੱਕੋ, "ptem");
	ioctl(*aslave, I_ਧੱਕੋ, "ldterm");
# ifndef __hpux
	ioctl(*aslave, I_ਧੱਕੋ, "ttcompat");
# endif /* __hpux */
	ਵਾਪਸ (0);
}
#ਜੇ_ਅੰਤ

ਪੂਰਨ
openpty(ਪੂਰਨ *amaster, ਪੂਰਨ *aslave, ਅੱਖਰ *name, ਅਚਲ ਬਣਤਰ termios *termp,
   ਅਚਲ ਬਣਤਰ winsize *winp)
{
#ਜੇ defined(HAVE__GETPTY)
	/*
	 * _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
	 * pty's automagically when needed
	 */
	ਅੱਖਰ *slave;

	ਜੇ ((slave = _getpty(amaster, O_RDWR, 0622, 0)) == ਨਿਰਾ)
		ਵਾਪਸ (-1);

	/* Open the slave side. */
	ਜੇ ((*aslave = open(slave, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		ਵਾਪਸ (-1);
	}
	ਵਾਪਸ (0);

#ਜਾਂਜੇ defined(HAVE_DEV_PTMX)

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSHD_ACQUIRES_CTTY
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
	ਪੂਰਨ r, fd;
	ਸਥਿਰ ਪੂਰਨ junk_ptyfd = -1, junk_ttyfd;
	ਅੱਖਰ *junk_name;

	r = openpty_streams(amaster, aslave);
	ਜੇ (junk_ptyfd == -1 && (fd = open(_PATH_TTY, O_RDWR|O_NOCTTY)) >= 0) {
		close(fd);
		junk_ptyfd = *amaster;
		junk_ttyfd = *aslave;
		junk_name = ttyname(junk_ttyfd);
		debug("STREAMS bug workaround pty %d tty %d name %s",
		    junk_ptyfd, junk_ttyfd, junk_name ? junk_name : "<none>");
	} ਨਹੀਂਤਾਂ
		ਵਾਪਸ r;
#ਜੇ_ਅੰਤ

	ਵਾਪਸ openpty_streams(amaster, aslave);

#ਜਾਂਜੇ defined(HAVE_DEV_PTS_AND_PTC)
	/* AIX-style pty code. */
	ਅਚਲ ਅੱਖਰ *ttname;

	ਜੇ ((*amaster = open("/dev/ptc", O_RDWR | O_NOCTTY)) == -1)
		ਵਾਪਸ (-1);
	ਜੇ ((ttname = ttyname(*amaster)) == ਨਿਰਾ)
		ਵਾਪਸ (-1);
	ਜੇ ((*aslave = open(ttname, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		ਵਾਪਸ (-1);
	}
	ਵਾਪਸ (0);

#ਨਹੀਂਤਾਂ
	/* BSD-style pty code. */
	ਅੱਖਰ ptbuf[64], ttbuf[64];
	ਪੂਰਨ i;
	ਅਚਲ ਅੱਖਰ *ptymajors = "pqrstuvwxyzabcdefghijklmno"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	ਅਚਲ ਅੱਖਰ *ptyminors = "0123456789abcdef";
	ਪੂਰਨ ਅੰਕ_minors = ਲੜੀ_ਲੰਬਾਈ(ptyminors);
	ਪੂਰਨ ਅੰਕ_ptys = ਲੜੀ_ਲੰਬਾਈ(ptymajors) * ਅੰਕ_minors;
	ਬਣਤਰ termios tio;

	ਲਈ (i = 0; i < ਅੰਕ_ptys; i++) {
		snprintf(ptbuf, ਆਕਾਰ(ptbuf), "/dev/pty%c%c",
		    ptymajors[i / ਅੰਕ_minors], ptyminors[i % ਅੰਕ_minors]);
		snprintf(ttbuf, ਆਕਾਰ(ttbuf), "/dev/tty%c%c",
		    ptymajors[i / ਅੰਕ_minors], ptyminors[i % ਅੰਕ_minors]);

		ਜੇ ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1) {
			/* Try SCO style naming */
			snprintf(ptbuf, ਆਕਾਰ(ptbuf), "/dev/ptyp%d", i);
			snprintf(ttbuf, ਆਕਾਰ(ttbuf), "/dev/ttyp%d", i);
			ਜੇ ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1)
				ਜਾਰੀ;
		}

		/* Open the slave side. */
		ਜੇ ((*aslave = open(ttbuf, O_RDWR | O_NOCTTY)) == -1) {
			close(*amaster);
			ਵਾਪਸ (-1);
		}
		/* set tty modes to a sane state for broken clients */
		ਜੇ (tcgetattr(*amaster, &tio) != -1) {
			tio.c_lflag |= (ECHO | ISIG | ICANON);
			tio.c_oflag |= (OPOST | ONLCR);
			tio.c_iflag |= ICRNL;
			tcsetattr(*amaster, TCSANOW, &tio);
		}

		ਵਾਪਸ (0);
	}
	ਵਾਪਸ (-1);
#ਜੇ_ਅੰਤ
}

#ਜੇ_ਅੰਤ /* !defined(HAVE_OPENPTY) */

