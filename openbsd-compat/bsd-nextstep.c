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

#شامل "includes.h"

#ifdef HAVE_NEXT
#شامل <errno.h>
#شامل <sys/wait.h>
#شامل "bsd-nextstep.h"

pid_t
posix_wait(صحیح *status)
{
	اجتماع wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	اگر (status)
		*status = (صحیح) statusp.w_status;

	بازگشت (wait_pid);
}

صحیح
tcgetattr(صحیح fd, ساختار termios *t)
{
	بازگشت (ioctl(fd, TIOCGETA, t));
}

صحیح
tcsetattr(صحیح fd, صحیح opt, ثابت ساختار termios *t)
{
	ساختار termios localterm;

	اگر (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	انتخاب (opt & ~TCSASOFT) {
	حالت TCSANOW:
		بازگشت (ioctl(fd, TIOCSETA, t));
	حالت TCSADRAIN:
		بازگشت (ioctl(fd, TIOCSETAW, t));
	حالت TCSAFLUSH:
		بازگشت (ioctl(fd, TIOCSETAF, t));
	پیشفرض:
		errno = EINVAL;
		بازگشت (-1);
	}
}

صحیح tcsetpgrp(صحیح fd, pid_t pgrp)
{
	بازگشت (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(ثابت ساختار termios *t)
{
	بازگشت (t->c_ospeed);
}

speed_t cfgetispeed(ثابت ساختار termios *t)
{
	بازگشت (t->c_ispeed);
}

صحیح
cfsetospeed(ساختار termios *t,صحیح speed)
{
	t->c_ospeed = speed;
	بازگشت (0);
}

صحیح
cfsetispeed(ساختار termios *t, صحیح speed)
{
	t->c_ispeed = speed;
	بازگشت (0);
}
#endif /* HAVE_NEXT */
