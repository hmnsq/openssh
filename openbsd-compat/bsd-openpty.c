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

#ضمن "includes.h"
#إذا !defined(HAVE_OPENPTY)

#ضمن <sys/types.h>

#ضمن <stdlib.h>
#ضمن <stdio.h>

#ضمن <sys/stat.h>
#که_تعریف_شوی HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#د_که_پای

#که_تعریف_شوی HAVE_FCNTL_H
# include <fcntl.h>
#د_که_پای

#ضمن <util.h>

#که_تعریف_شوی HAVE_PTY_H
# include <pty.h>
#د_که_پای
#إذا defined(HAVE_DEV_PTMX) && defined(HAVE_SYS_STROPTS_H)
# include <sys/stropts.h>
#د_که_پای

#ضمن <signal.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "misc.h"
#ضمن "log.h"

#که_نه_تعریف_شوی O_NOCTTY
#تعریف_کړه O_NOCTTY 0
#د_که_پای

#إذا defined(HAVE_DEV_PTMX) && !defined(HAVE__GETPTY)
ساكن صحيح
openpty_streams(صحيح *amaster, صحيح *aslave)
{
	/*
	 * This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3
	 * also has bsd-style ptys, but they simply do not work.)
	 */
	صحيح ptm;
	حرف *pts;
	sshsig_t old_signal;

	إذا ((ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY)) == -1)
		أرجع (-1);

	/* XXX: need to close ptm on error? */
	old_signal = ssh_signal(SIGCHLD, SIG_DFL);
	إذا (grantpt(ptm) < 0)
		أرجع (-1);
	ssh_signal(SIGCHLD, old_signal);

	إذا (unlockpt(ptm) < 0)
		أرجع (-1);

	إذا ((pts = ptsname(ptm)) == عدم)
		أرجع (-1);
	*amaster = ptm;

	/* Open the slave side. */
	إذا ((*aslave = open(pts, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		أرجع (-1);
	}

# إذا defined(I_پیدا_کړه) && defined(__SVR4)
	/*
	 * If the streams modules have already been pushed then there
	 * is no more work to do here.
	 */
	إذا (ioctl(*aslave, I_پیدا_کړه, "ptem") != 0)
		أرجع 0;
# endif

	/*
	 * Try to push the appropriate streams modules, as described
	 * in Solaris pts(7).
	 */
	ioctl(*aslave, I_ټېل, "ptem");
	ioctl(*aslave, I_ټېل, "ldterm");
# ifndef __hpux
	ioctl(*aslave, I_ټېل, "ttcompat");
# endif /* __hpux */
	أرجع (0);
}
#د_که_پای

صحيح
openpty(صحيح *amaster, صحيح *aslave, حرف *name, ثابت بنية termios *termp,
   ثابت بنية winsize *winp)
{
#إذا defined(HAVE__GETPTY)
	/*
	 * _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
	 * pty's automagically when needed
	 */
	حرف *slave;

	إذا ((slave = _getpty(amaster, O_RDWR, 0622, 0)) == عدم)
		أرجع (-1);

	/* Open the slave side. */
	إذا ((*aslave = open(slave, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		أرجع (-1);
	}
	أرجع (0);

#وإلاإذا defined(HAVE_DEV_PTMX)

#که_تعریف_شوی SSHD_ACQUIRES_CTTY
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
	صحيح r, fd;
	ساكن صحيح junk_ptyfd = -1, junk_ttyfd;
	حرف *junk_name;

	r = openpty_streams(amaster, aslave);
	إذا (junk_ptyfd == -1 && (fd = open(_PATH_TTY, O_RDWR|O_NOCTTY)) >= 0) {
		close(fd);
		junk_ptyfd = *amaster;
		junk_ttyfd = *aslave;
		junk_name = ttyname(junk_ttyfd);
		debug("STREAMS bug workaround pty %d tty %d name %s",
		    junk_ptyfd, junk_ttyfd, junk_name ? junk_name : "<none>");
	} وإلا
		أرجع r;
#د_که_پای

	أرجع openpty_streams(amaster, aslave);

#وإلاإذا defined(HAVE_DEV_PTS_AND_PTC)
	/* AIX-style pty code. */
	ثابت حرف *ttname;

	إذا ((*amaster = open("/dev/ptc", O_RDWR | O_NOCTTY)) == -1)
		أرجع (-1);
	إذا ((ttname = ttyname(*amaster)) == عدم)
		أرجع (-1);
	إذا ((*aslave = open(ttname, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		أرجع (-1);
	}
	أرجع (0);

#وإلا
	/* BSD-style pty code. */
	حرف ptbuf[64], ttbuf[64];
	صحيح i;
	ثابت حرف *ptymajors = "pqrstuvwxyzabcdefghijklmno"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	ثابت حرف *ptyminors = "0123456789abcdef";
	صحيح عدد_minors = مزي_اوږدوالی(ptyminors);
	صحيح عدد_ptys = مزي_اوږدوالی(ptymajors) * عدد_minors;
	بنية termios tio;

	لكل (i = 0; i < عدد_ptys; i++) {
		snprintf(ptbuf, حجم(ptbuf), "/dev/pty%c%c",
		    ptymajors[i / عدد_minors], ptyminors[i % عدد_minors]);
		snprintf(ttbuf, حجم(ttbuf), "/dev/tty%c%c",
		    ptymajors[i / عدد_minors], ptyminors[i % عدد_minors]);

		إذا ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1) {
			/* Try SCO style naming */
			snprintf(ptbuf, حجم(ptbuf), "/dev/ptyp%d", i);
			snprintf(ttbuf, حجم(ttbuf), "/dev/ttyp%d", i);
			إذا ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1)
				استمر;
		}

		/* Open the slave side. */
		إذا ((*aslave = open(ttbuf, O_RDWR | O_NOCTTY)) == -1) {
			close(*amaster);
			أرجع (-1);
		}
		/* set tty modes to a sane state for broken clients */
		إذا (tcgetattr(*amaster, &tio) != -1) {
			tio.c_lflag |= (ECHO | ISIG | ICANON);
			tio.c_oflag |= (OPOST | ONLCR);
			tio.c_iflag |= ICRNL;
			tcsetattr(*amaster, TCSANOW, &tio);
		}

		أرجع (0);
	}
	أرجع (-1);
#د_که_پای
}

#د_که_پای /* !defined(HAVE_OPENPTY) */

