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
posix_wait(ຈຳນວນເຕັມ *status)
{
	sa_ngha wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	ຖ້າ (status)
		*status = (ຈຳນວນເຕັມ) statusp.w_status;

	ສົ່ງຄືນ (wait_pid);
}

ຈຳນວນເຕັມ
tcgetattr(ຈຳນວນເຕັມ fd, sa_nracanaa termios *t)
{
	ສົ່ງຄືນ (ioctl(fd, TIOCGETA, t));
}

ຈຳນວນເຕັມ
tcsetattr(ຈຳນວນເຕັມ fd, ຈຳນວນເຕັມ opt, const sa_nracanaa termios *t)
{
	sa_nracanaa termios localterm;

	ຖ້າ (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	switch (opt & ~TCSASOFT) {
	pak_sa TCSANOW:
		ສົ່ງຄືນ (ioctl(fd, TIOCSETA, t));
	pak_sa TCSADRAIN:
		ສົ່ງຄືນ (ioctl(fd, TIOCSETAW, t));
	pak_sa TCSAFLUSH:
		ສົ່ງຄືນ (ioctl(fd, TIOCSETAF, t));
	default:
		errno = EINVAL;
		ສົ່ງຄືນ (-1);
	}
}

ຈຳນວນເຕັມ tcsetpgrp(ຈຳນວນເຕັມ fd, pid_t pgrp)
{
	ສົ່ງຄືນ (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(const sa_nracanaa termios *t)
{
	ສົ່ງຄືນ (t->c_ospeed);
}

speed_t cfgetispeed(const sa_nracanaa termios *t)
{
	ສົ່ງຄືນ (t->c_ispeed);
}

ຈຳນວນເຕັມ
cfsetospeed(sa_nracanaa termios *t,ຈຳນວນເຕັມ speed)
{
	t->c_ospeed = speed;
	ສົ່ງຄືນ (0);
}

ຈຳນວນເຕັມ
cfsetispeed(sa_nracanaa termios *t, ຈຳນວນເຕັມ speed)
{
	t->c_ispeed = speed;
	ສົ່ງຄືນ (0);
}
#endif /* HAVE_NEXT */
