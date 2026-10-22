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

#اگر_تعریف_شدہ HAVE_اگلا
#شامل <errno.h>
#شامل <sys/wait.h>
#شامل "bsd-nextstep.h"

pid_t
posix_wait(صحیح *حالت_2)
{
	اتحاد wait statusp;
	pid_t wait_pid;

	#تعریف_منسوخ wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	اگر (حالت_2)
		*حالت_2 = (صحیح) statusp.w_حالت;

	واپس (wait_pid);
}

صحیح
tcgetattr(صحیح fd, ساخت termios *t)
{
	واپس (ioctl(fd, TIOCGETA, t));
}

صحیح
tcsetattr(صحیح fd, صحیح opt, ثابت ساخت termios *t)
{
	ساخت termios localterm;

	اگر (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	انتخاب (opt & ~TCSASOFT) {
	حالت TCSANOW:
		واپس (ioctl(fd, TIOCSETA, t));
	حالت TCSADRAIN:
		واپس (ioctl(fd, TIOCSETAW, t));
	حالت TCSAFLUSH:
		واپس (ioctl(fd, TIOCSETAF, t));
	طےشدہ:
		errno = EINVAL;
		واپس (-1);
	}
}

صحیح tcsetpgrp(صحیح fd, pid_t pgrp)
{
	واپس (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(ثابت ساخت termios *t)
{
	واپس (t->c_ospeed);
}

speed_t cfgetispeed(ثابت ساخت termios *t)
{
	واپس (t->c_ispeed);
}

صحیح
cfsetospeed(ساخت termios *t,صحیح رفتار)
{
	t->c_ospeed = رفتار;
	واپس (0);
}

صحیح
cfsetispeed(ساخت termios *t, صحیح رفتار)
{
	t->c_ispeed = رفتار;
	واپس (0);
}
#اگر_ختم /* HAVE_NEXT */
