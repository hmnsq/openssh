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
posix_wait(정수 *status)
{
	union wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	만약 (status)
		*status = (정수) statusp.w_status;

	반환 (wait_pid);
}

정수
tcgetattr(정수 fd, struct termios *t)
{
	반환 (ioctl(fd, TIOCGETA, t));
}

정수
tcsetattr(정수 fd, 정수 opt, const struct termios *t)
{
	struct termios localterm;

	만약 (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	switch (opt & ~TCSASOFT) {
	case TCSANOW:
		반환 (ioctl(fd, TIOCSETA, t));
	case TCSADRAIN:
		반환 (ioctl(fd, TIOCSETAW, t));
	case TCSAFLUSH:
		반환 (ioctl(fd, TIOCSETAF, t));
	default:
		errno = EINVAL;
		반환 (-1);
	}
}

정수 tcsetpgrp(정수 fd, pid_t pgrp)
{
	반환 (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(const struct termios *t)
{
	반환 (t->c_ospeed);
}

speed_t cfgetispeed(const struct termios *t)
{
	반환 (t->c_ispeed);
}

정수
cfsetospeed(struct termios *t,정수 speed)
{
	t->c_ospeed = speed;
	반환 (0);
}

정수
cfsetispeed(struct termios *t, 정수 speed)
{
	t->c_ispeed = speed;
	반환 (0);
}
#endif /* HAVE_NEXT */
