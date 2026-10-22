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
posix_wait(整数 *status)
{
	union wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	如果 (status)
		*status = (整数) statusp.w_status;

	返回 (wait_pid);
}

整数
tcgetattr(整数 fd, struct termios *t)
{
	返回 (ioctl(fd, TIOCGETA, t));
}

整数
tcsetattr(整数 fd, 整数 opt, const struct termios *t)
{
	struct termios localterm;

	如果 (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	switch (opt & ~TCSASOFT) {
	case TCSANOW:
		返回 (ioctl(fd, TIOCSETA, t));
	case TCSADRAIN:
		返回 (ioctl(fd, TIOCSETAW, t));
	case TCSAFLUSH:
		返回 (ioctl(fd, TIOCSETAF, t));
	default:
		errno = EINVAL;
		返回 (-1);
	}
}

整数 tcsetpgrp(整数 fd, pid_t pgrp)
{
	返回 (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(const struct termios *t)
{
	返回 (t->c_ospeed);
}

speed_t cfgetispeed(const struct termios *t)
{
	返回 (t->c_ispeed);
}

整数
cfsetospeed(struct termios *t,整数 speed)
{
	t->c_ospeed = speed;
	返回 (0);
}

整数
cfsetispeed(struct termios *t, 整数 speed)
{
	t->c_ispeed = speed;
	返回 (0);
}
#endif /* HAVE_NEXT */
