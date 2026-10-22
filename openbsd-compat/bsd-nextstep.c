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
posix_wait(целое *status)
{
	union wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	если (status)
		*status = (целое) statusp.w_status;

	вернуть (wait_pid);
}

целое
tcgetattr(целое fd, struct termios *t)
{
	вернуть (ioctl(fd, TIOCGETA, t));
}

целое
tcsetattr(целое fd, целое opt, const struct termios *t)
{
	struct termios localterm;

	если (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	switch (opt & ~TCSASOFT) {
	case TCSANOW:
		вернуть (ioctl(fd, TIOCSETA, t));
	case TCSADRAIN:
		вернуть (ioctl(fd, TIOCSETAW, t));
	case TCSAFLUSH:
		вернуть (ioctl(fd, TIOCSETAF, t));
	default:
		errno = EINVAL;
		вернуть (-1);
	}
}

целое tcsetpgrp(целое fd, pid_t pgrp)
{
	вернуть (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(const struct termios *t)
{
	вернуть (t->c_ospeed);
}

speed_t cfgetispeed(const struct termios *t)
{
	вернуть (t->c_ispeed);
}

целое
cfsetospeed(struct termios *t,целое speed)
{
	t->c_ospeed = speed;
	вернуть (0);
}

целое
cfsetispeed(struct termios *t, целое speed)
{
	t->c_ispeed = speed;
	вернуть (0);
}
#endif /* HAVE_NEXT */
