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

#અન્તર્ભાવ "includes.h"

#ifdef HAVE_NEXT
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <sys/wait.h>
#અન્તર્ભાવ "bsd-nextstep.h"

pid_t
posix_wait(પૂર્ણાંક *status)
{
	સંઘ wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	જો (status)
		*status = (પૂર્ણાંક) statusp.w_status;

	પાછા (wait_pid);
}

પૂર્ણાંક
tcgetattr(પૂર્ણાંક fd, સંરચના termios *t)
{
	પાછા (ioctl(fd, TIOCGETA, t));
}

પૂર્ણાંક
tcsetattr(પૂર્ણાંક fd, પૂર્ણાંક opt, અચલ સંરચના termios *t)
{
	સંરચના termios localterm;

	જો (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	પસંદગી (opt & ~TCSASOFT) {
	સ્થિતિ TCSANOW:
		પાછા (ioctl(fd, TIOCSETA, t));
	સ્થિતિ TCSADRAIN:
		પાછા (ioctl(fd, TIOCSETAW, t));
	સ્થિતિ TCSAFLUSH:
		પાછા (ioctl(fd, TIOCSETAF, t));
	મૂળભૂત:
		errno = EINVAL;
		પાછા (-1);
	}
}

પૂર્ણાંક tcsetpgrp(પૂર્ણાંક fd, pid_t pgrp)
{
	પાછા (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(અચલ સંરચના termios *t)
{
	પાછા (t->c_ospeed);
}

speed_t cfgetispeed(અચલ સંરચના termios *t)
{
	પાછા (t->c_ispeed);
}

પૂર્ણાંક
cfsetospeed(સંરચના termios *t,પૂર્ણાંક speed)
{
	t->c_ospeed = speed;
	પાછા (0);
}

પૂર્ણાંક
cfsetispeed(સંરચના termios *t, પૂર્ણાંક speed)
{
	t->c_ispeed = speed;
	પાછા (0);
}
#endif /* HAVE_NEXT */
