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

#অন্তর্ভাব "includes.h"

#ifdef HAVE_NEXT
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <sys/wait.h>
#অন্তর্ভাব "bsd-nextstep.h"

pid_t
posix_wait(পূর্ণাঙ্ক *status)
{
	সঙ্ঘ wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	যদি (status)
		*status = (পূর্ণাঙ্ক) statusp.w_status;

	প্রত্যাগম (wait_pid);
}

পূর্ণাঙ্ক
tcgetattr(পূর্ণাঙ্ক fd, সংরচনা termios *t)
{
	প্রত্যাগম (ioctl(fd, TIOCGETA, t));
}

পূর্ণাঙ্ক
tcsetattr(পূর্ণাঙ্ক fd, পূর্ণাঙ্ক opt, ধ্রুব সংরচনা termios *t)
{
	সংরচনা termios localterm;

	যদি (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	বিকল্প (opt & ~TCSASOFT) {
	পক্ষ TCSANOW:
		প্রত্যাগম (ioctl(fd, TIOCSETA, t));
	পক্ষ TCSADRAIN:
		প্রত্যাগম (ioctl(fd, TIOCSETAW, t));
	পক্ষ TCSAFLUSH:
		প্রত্যাগম (ioctl(fd, TIOCSETAF, t));
	স্বভাব:
		errno = EINVAL;
		প্রত্যাগম (-1);
	}
}

পূর্ণাঙ্ক tcsetpgrp(পূর্ণাঙ্ক fd, pid_t pgrp)
{
	প্রত্যাগম (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(ধ্রুব সংরচনা termios *t)
{
	প্রত্যাগম (t->c_ospeed);
}

speed_t cfgetispeed(ধ্রুব সংরচনা termios *t)
{
	প্রত্যাগম (t->c_ispeed);
}

পূর্ণাঙ্ক
cfsetospeed(সংরচনা termios *t,পূর্ণাঙ্ক speed)
{
	t->c_ospeed = speed;
	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
cfsetispeed(সংরচনা termios *t, পূর্ণাঙ্ক speed)
{
	t->c_ispeed = speed;
	প্রত্যাগম (0);
}
#endif /* HAVE_NEXT */
