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
posix_wait(ཧྲིལ *status)
{
	sa_ngha wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	གལ་སྲིད (status)
		*status = (ཧྲིལ) statusp.w_status;

	ལོག (wait_pid);
}

ཧྲིལ
tcgetattr(ཧྲིལ fd, sa_nracanaa termios *t)
{
	ལོག (ioctl(fd, TIOCGETA, t));
}

ཧྲིལ
tcsetattr(ཧྲིལ fd, ཧྲིལ opt, const sa_nracanaa termios *t)
{
	sa_nracanaa termios localterm;

	གལ་སྲིད (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	switch (opt & ~TCSASOFT) {
	pak_sa TCSANOW:
		ལོག (ioctl(fd, TIOCSETA, t));
	pak_sa TCSADRAIN:
		ལོག (ioctl(fd, TIOCSETAW, t));
	pak_sa TCSAFLUSH:
		ལོག (ioctl(fd, TIOCSETAF, t));
	default:
		errno = EINVAL;
		ལོག (-1);
	}
}

ཧྲིལ tcsetpgrp(ཧྲིལ fd, pid_t pgrp)
{
	ལོག (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(const sa_nracanaa termios *t)
{
	ལོག (t->c_ospeed);
}

speed_t cfgetispeed(const sa_nracanaa termios *t)
{
	ལོག (t->c_ispeed);
}

ཧྲིལ
cfsetospeed(sa_nracanaa termios *t,ཧྲིལ speed)
{
	t->c_ospeed = speed;
	ལོག (0);
}

ཧྲིལ
cfsetispeed(sa_nracanaa termios *t, ཧྲིལ speed)
{
	t->c_ispeed = speed;
	ལོག (0);
}
#endif /* HAVE_NEXT */
