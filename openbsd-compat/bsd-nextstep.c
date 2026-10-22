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

#ضمن "includes.h"

#ifdef HAVE_NEXT
#ضمن <errno.h>
#ضمن <sys/wait.h>
#ضمن "bsd-nextstep.h"

pid_t
posix_wait(صحيح *status)
{
	اتحاد wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	אם (status)
		*status = (صحيح) statusp.w_status;

	החזר (wait_pid);
}

صحيح
tcgetattr(صحيح fd, بنية termios *t)
{
	החזר (ioctl(fd, TIOCGETA, t));
}

صحيح
tcsetattr(صحيح fd, صحيح opt, ثابت بنية termios *t)
{
	بنية termios localterm;

	אם (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	بدل (opt & ~TCSASOFT) {
	حالة TCSANOW:
		החזר (ioctl(fd, TIOCSETA, t));
	حالة TCSADRAIN:
		החזר (ioctl(fd, TIOCSETAW, t));
	حالة TCSAFLUSH:
		החזר (ioctl(fd, TIOCSETAF, t));
	افتراضي:
		errno = EINVAL;
		החזר (-1);
	}
}

صحيح tcsetpgrp(صحيح fd, pid_t pgrp)
{
	החזר (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(ثابت بنية termios *t)
{
	החזר (t->c_ospeed);
}

speed_t cfgetispeed(ثابت بنية termios *t)
{
	החזר (t->c_ispeed);
}

صحيح
cfsetospeed(بنية termios *t,صحيح speed)
{
	t->c_ospeed = speed;
	החזר (0);
}

صحيح
cfsetispeed(بنية termios *t, صحيح speed)
{
	t->c_ispeed = speed;
	החזר (0);
}
#endif /* HAVE_NEXT */
