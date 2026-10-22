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

#شامل "includes.h"
#اگر !defined(HAVE_OPENPTY)

#شامل <sys/types.h>

#شامل <stdlib.h>
#شامل <stdio.h>

#شامل <sys/stat.h>
#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#شامل <util.h>

#ifdef HAVE_PTY_H
# include <pty.h>
#endif
#اگر defined(HAVE_DEV_PTMX) && defined(HAVE_SYS_STROPTS_H)
# include <sys/stropts.h>
#endif

#شامل <signal.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "misc.h"
#شامل "log.h"

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

#اگر defined(HAVE_DEV_PTMX) && !defined(HAVE__GETPTY)
ایستا صحیح
openpty_streams(صحیح *amaster, صحیح *aslave)
{
	/*
	 * This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3
	 * also has bsd-style ptys, but they simply do not work.)
	 */
	صحیح ptm;
	نویسه *pts;
	sshsig_t old_signal;

	اگر ((ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY)) == -1)
		بازگشت (-1);

	/* XXX: need to close ptm on error? */
	old_signal = ssh_signal(SIGCHLD, SIG_DFL);
	اگر (grantpt(ptm) < 0)
		بازگشت (-1);
	ssh_signal(SIGCHLD, old_signal);

	اگر (unlockpt(ptm) < 0)
		بازگشت (-1);

	اگر ((pts = ptsname(ptm)) == پوچ)
		بازگشت (-1);
	*amaster = ptm;

	/* Open the slave side. */
	اگر ((*aslave = open(pts, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		بازگشت (-1);
	}

# اگر defined(I_FIND) && defined(__SVR4)
	/*
	 * If the streams modules have already been pushed then there
	 * is no more work to do here.
	 */
	اگر (ioctl(*aslave, I_FIND, "ptem") != 0)
		بازگشت 0;
# endif

	/*
	 * Try to push the appropriate streams modules, as described
	 * in Solaris pts(7).
	 */
	ioctl(*aslave, I_افزودن, "ptem");
	ioctl(*aslave, I_افزودن, "ldterm");
# ifndef __hpux
	ioctl(*aslave, I_افزودن, "ttcompat");
# endif /* __hpux */
	بازگشت (0);
}
#endif

صحیح
openpty(صحیح *amaster, صحیح *aslave, نویسه *name, ثابت ساختار termios *termp,
   ثابت ساختار winsize *winp)
{
#اگر defined(HAVE__GETPTY)
	/*
	 * _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
	 * pty's automagically when needed
	 */
	نویسه *slave;

	اگر ((slave = _getpty(amaster, O_RDWR, 0622, 0)) == پوچ)
		بازگشت (-1);

	/* Open the slave side. */
	اگر ((*aslave = open(slave, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		بازگشت (-1);
	}
	بازگشت (0);

#وگرنهاگر defined(HAVE_DEV_PTMX)

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
	صحیح r, fd;
	ایستا صحیح junk_ptyfd = -1, junk_ttyfd;
	نویسه *junk_name;

	r = openpty_streams(amaster, aslave);
	اگر (junk_ptyfd == -1 && (fd = open(_PATH_TTY, O_RDWR|O_NOCTTY)) >= 0) {
		close(fd);
		junk_ptyfd = *amaster;
		junk_ttyfd = *aslave;
		junk_name = ttyname(junk_ttyfd);
		debug("STREAMS bug workaround pty %d tty %d name %s",
		    junk_ptyfd, junk_ttyfd, junk_name ? junk_name : "<none>");
	} وگرنه
		بازگشت r;
#endif

	بازگشت openpty_streams(amaster, aslave);

#وگرنهاگر defined(HAVE_DEV_PTS_AND_PTC)
	/* AIX-style pty code. */
	ثابت نویسه *ttname;

	اگر ((*amaster = open("/dev/ptc", O_RDWR | O_NOCTTY)) == -1)
		بازگشت (-1);
	اگر ((ttname = ttyname(*amaster)) == پوچ)
		بازگشت (-1);
	اگر ((*aslave = open(ttname, O_RDWR | O_NOCTTY)) == -1) {
		close(*amaster);
		بازگشت (-1);
	}
	بازگشت (0);

#وگرنه
	/* BSD-style pty code. */
	نویسه ptbuf[64], ttbuf[64];
	صحیح i;
	ثابت نویسه *ptymajors = "pqrstuvwxyzabcdefghijklmno"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	ثابت نویسه *ptyminors = "0123456789abcdef";
	صحیح رقم_minors = strlen(ptyminors);
	صحیح رقم_ptys = strlen(ptymajors) * رقم_minors;
	ساختار termios tio;

	برای (i = 0; i < رقم_ptys; i++) {
		snprintf(ptbuf, اندازه(ptbuf), "/dev/pty%c%c",
		    ptymajors[i / رقم_minors], ptyminors[i % رقم_minors]);
		snprintf(ttbuf, اندازه(ttbuf), "/dev/tty%c%c",
		    ptymajors[i / رقم_minors], ptyminors[i % رقم_minors]);

		اگر ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1) {
			/* Try SCO style naming */
			snprintf(ptbuf, اندازه(ptbuf), "/dev/ptyp%d", i);
			snprintf(ttbuf, اندازه(ttbuf), "/dev/ttyp%d", i);
			اگر ((*amaster = open(ptbuf, O_RDWR | O_NOCTTY)) == -1)
				ادامه;
		}

		/* Open the slave side. */
		اگر ((*aslave = open(ttbuf, O_RDWR | O_NOCTTY)) == -1) {
			close(*amaster);
			بازگشت (-1);
		}
		/* set tty modes to a sane state for broken clients */
		اگر (tcgetattr(*amaster, &tio) != -1) {
			tio.c_lflag |= (ECHO | ISIG | ICANON);
			tio.c_oflag |= (OPOST | ONLCR);
			tio.c_iflag |= ICRNL;
			tcsetattr(*amaster, TCSANOW, &tio);
		}

		بازگشت (0);
	}
	بازگشت (-1);
#endif
}

#endif /* !defined(HAVE_OPENPTY) */

