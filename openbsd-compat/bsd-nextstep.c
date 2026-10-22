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
posix_wait(số_nguyên *status)
{
	union wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	nếu (status)
		*status = (số_nguyên) statusp.w_status;

	trả_về (wait_pid);
}

số_nguyên
tcgetattr(số_nguyên fd, struct termios *t)
{
	trả_về (ioctl(fd, TIOCGETA, t));
}

số_nguyên
tcsetattr(số_nguyên fd, số_nguyên opt, const struct termios *t)
{
	struct termios localterm;

	nếu (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	switch (opt & ~TCSASOFT) {
	case TCSANOW:
		trả_về (ioctl(fd, TIOCSETA, t));
	case TCSADRAIN:
		trả_về (ioctl(fd, TIOCSETAW, t));
	case TCSAFLUSH:
		trả_về (ioctl(fd, TIOCSETAF, t));
	default:
		errno = EINVAL;
		trả_về (-1);
	}
}

số_nguyên tcsetpgrp(số_nguyên fd, pid_t pgrp)
{
	trả_về (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(const struct termios *t)
{
	trả_về (t->c_ospeed);
}

speed_t cfgetispeed(const struct termios *t)
{
	trả_về (t->c_ispeed);
}

số_nguyên
cfsetospeed(struct termios *t,số_nguyên speed)
{
	t->c_ospeed = speed;
	trả_về (0);
}

số_nguyên
cfsetispeed(struct termios *t, số_nguyên speed)
{
	t->c_ispeed = speed;
	trả_về (0);
}
#endif /* HAVE_NEXT */
