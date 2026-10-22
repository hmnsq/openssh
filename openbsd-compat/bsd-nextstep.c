/*
 * Copyright (c) 2000,2001 Ben Lindstrom.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#ifdef HAVE_NEXT
#include <errno.h>
#include <sys/wait.h>
#include "bsd-nextstep.h"

pid_t
posix_wait(จำนวนเต็ม *status)
{
	sa_ngha wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	ถ้า (status)
		*status = (จำนวนเต็ม) statusp.w_status;

	คืน (wait_pid);
}

จำนวนเต็ม
tcgetattr(จำนวนเต็ม fd, sa_nracanaa termios *t)
{
	คืน (ioctl(fd, TIOCGETA, t));
}

จำนวนเต็ม
tcsetattr(จำนวนเต็ม fd, จำนวนเต็ม opt, const sa_nracanaa termios *t)
{
	sa_nracanaa termios localterm;

	ถ้า (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	switch (opt & ~TCSASOFT) {
	pak_sa TCSANOW:
		คืน (ioctl(fd, TIOCSETA, t));
	pak_sa TCSADRAIN:
		คืน (ioctl(fd, TIOCSETAW, t));
	pak_sa TCSAFLUSH:
		คืน (ioctl(fd, TIOCSETAF, t));
	default:
		errno = EINVAL;
		คืน (-1);
	}
}

จำนวนเต็ม tcsetpgrp(จำนวนเต็ม fd, pid_t pgrp)
{
	คืน (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(const sa_nracanaa termios *t)
{
	คืน (t->c_ospeed);
}

speed_t cfgetispeed(const sa_nracanaa termios *t)
{
	คืน (t->c_ispeed);
}

จำนวนเต็ม
cfsetospeed(sa_nracanaa termios *t,จำนวนเต็ม speed)
{
	t->c_ospeed = speed;
	คืน (0);
}

จำนวนเต็ม
cfsetispeed(sa_nracanaa termios *t, จำนวนเต็ม speed)
{
	t->c_ispeed = speed;
	คืน (0);
}
#endif /* HAVE_NEXT */
