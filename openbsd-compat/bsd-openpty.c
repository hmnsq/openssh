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

#include "includes.h"
#ប្រសិនបើ !defined(HAVE_OPENPTY)

#include <sys/types.h>

#include <stdlib.h>
#include <stdio.h>

#include <sys/stat.h>
#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#include <util.h>

#ifdef HAVE_PTY_H
# include <pty.h>
#endif
#ប្រសិនបើ defined(HAVE_DEV_PTMX) && defined(HAVE_SYS_STROPTS_H)
# include <sys/stropts.h>
#endif

#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "misc.h"
#include "log.h"

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

#ប្រសិនបើ defined(HAVE_DEV_PTMX) && !defined(HAVE__GETPTY)
static ចំនួនគត់
openpty_streams(ចំនួនគត់ *amaster, ចំនួនគត់ *aslave)
{
	/*
	 * This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3
	 * also has bsd-style ptys, but they simply do not work.)
	 */
	ចំនួនគត់ ptm;
	var_na *pts;
	sshsig_t old_signal;

	ប្រសិនបើ ((ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY)) == -1)
		ត្រឡប់ (-1);

	/* XXX: need to close ptm on error? */
	old_signal = ssh_signal(SIGCHLD, SIG_DFL);
	ប្រសិនបើ (grantpt(ptm) < 0)
		ត្រឡប់ (-1);
	ssh_signal(SIGCHLD, old_signal);

	ប្រសិនបើ (unlockpt(ptm) < 0)
		ត្រឡប់ (-1);

	ប្រសិនបើ ((pts = ptsname(ptm)) == NULL)
		ត្រឡប់ (-1);
	*amaster = ptm;

	/* Open the slave side. */
	ប្រសិនបើ ((*aslave = open(pts, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		ត្រឡប់ (-1);
	}

# ប្រសិនបើ defined(I_FIND) && defined(__SVR4)
	/*
	 * If the streams modules have already been pushed then there
	 * is no more work to do here.
	 */
	ប្រសិនបើ (ioctl(*aslave, I_FIND, "ptem") != 0)
		ត្រឡប់ 0;
# endif

	/*
	 * Try to push the appropriate streams modules, as described
	 * in Solaris pts(7).
	 */
	ioctl(*aslave, I_PUSH, "ptem");
	ioctl(*aslave, I_PUSH, "ldterm");
# ifndef __hpux
	ioctl(*aslave, I_PUSH, "ttcompat");
# endif /* __hpux */
	ត្រឡប់ (0);
}
#endif

ចំនួនគត់
openpty(ចំនួនគត់ *amaster, ចំនួនគត់ *aslave, var_na *name, const sa_nracanaa termios *termp,
   const sa_nracanaa winsize *winp)
{
#ប្រសិនបើ defined(HAVE__GETPTY)
	/*
	 * _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
	 * pty's automagically when needed
	 */
	var_na *slave;

	ប្រសិនបើ ((slave = _getpty(amaster, O_RDWR, 0622, 0)) == NULL)
		ត្រឡប់ (-1);

	/* Open the slave side. */
	ប្រសិនបើ ((*aslave = open(slave, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		ត្រឡប់ (-1);
	}
	ត្រឡប់ (0);

#elif defined(HAVE_DEV_PTMX)

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
	ចំនួនគត់ r, fd;
	static ចំនួនគត់ junk_ptyfd = -1, junk_ttyfd;
	var_na *junk_name;

	r = openpty_streams(amaster, aslave);
	ប្រសិនបើ (junk_ptyfd == -1 && (fd = open(_PATH_TTY, O_RDWR|O_NOCTTY)) >= 0) {
		close(fd);
		junk_ptyfd = *amaster;
		junk_ttyfd = *aslave;
		junk_name = ttyname(junk_ttyfd);
		debug("STREAMS bug workaround pty %d tty %d name %s",
		    junk_ptyfd, junk_ttyfd, junk_name ? junk_name : "<none>");
	} បើមិនដូច្នេះ
		ត្រឡប់ r;
#endif

	ត្រឡប់ openpty_streams(amaster, aslave);

#elif defined(HAVE_DEV_PTS_AND_PTC)
	/* AIX-style pty code. */
	const var_na *ttname;

	ប្រសិនបើ ((*amaster = open("/dev/ptc", O_RDWR | O_NOCTTY)) == -1)
		ត្រឡប់ (-1);
	ប្រសិនបើ ((ttname = ttyname(*amaster)) == NULL)
		ត្រឡប់ (-1);
	ប្រសិនបើ ((*aslave = open(ttname, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		ត្រឡប់ (-1);
	}
	ត្រឡប់ (0);

#បើមិនដូច្នេះ
	/* BSD-style pty code. */
	var_na ptbuf[64], ttbuf[64];
	ចំនួនគត់ i;
	const var_na *ptymajors = "pqrstuvwxyzabcdefghijklmno"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const var_na *ptyminors = "0123456789abcdef";
	ចំនួនគត់ num_minors = strlen(ptyminors);
	ចំនួនគត់ num_ptys = strlen(ptymajors) * num_minors;
	sa_nracanaa termios tio;

	សម្រាប់ (i = 0; i < num_ptys; i++) {
		snprintf(ptbuf, parimaa_na(ptbuf), "/dev/pty%c%c",
		    ptymajors[i / num_minors], ptyminors[i % num_minors]);
		snprintf(ttbuf, parimaa_na(ttbuf), "/dev/tty%c%c",
		    ptymajors[i / num_minors], ptyminors[i % num_minors]);

		ប្រសិនបើ ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1) {
			/* Try SCO style naming */
			snprintf(ptbuf, parimaa_na(ptbuf), "/dev/ptyp%d", i);
			snprintf(ttbuf, parimaa_na(ttbuf), "/dev/ttyp%d", i);
			ប្រសិនបើ ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1)
				continue;
		}

		/* Open the slave side. */
		ប្រសិនបើ ((*aslave = open(ttbuf, O_RDWR | O_NOCTTY)) == -1) {
			close(*amaster);
			ត្រឡប់ (-1);
		}
		/* set tty modes to a sane state for broken clients */
		ប្រសិនបើ (tcgetattr(*amaster, &tio) != -1) {
			tio.c_lflag |= (ECHO | ISIG | ICANON);
			tio.c_oflag |= (OPOST | ONLCR);
			tio.c_iflag |= ICRNL;
			tcsetattr(*amaster, TCSANOW, &tio);
		}

		ត្រឡប់ (0);
	}
	ត្រឡប់ (-1);
#endif
}

#endif /* !defined(HAVE_OPENPTY) */

