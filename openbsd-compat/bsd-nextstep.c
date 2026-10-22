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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే HAVE_తదుపరి
#అన్తర్భావ <errno.h>
#అన్తర్భావ <sys/wait.h>
#అన్తర్భావ "bsd-nextstep.h"

pid_t
posix_wait(పూర్ణాంకం *స్థితి_2)
{
	సంఘం wait statusp;
	pid_t wait_pid;

	#నిర్వచనం_రద్దు wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	ఒకవేళ (స్థితి_2)
		*స్థితి_2 = (పూర్ణాంకం) statusp.w_స్థితి;

	తిరిగి (wait_pid);
}

పూర్ణాంకం
tcgetattr(పూర్ణాంకం fd, నిర్మాణం termios *t)
{
	తిరిగి (ioctl(fd, TIOCGETA, t));
}

పూర్ణాంకం
tcsetattr(పూర్ణాంకం fd, పూర్ణాంకం opt, స్థిరరాశి నిర్మాణం termios *t)
{
	నిర్మాణం termios localterm;

	ఒకవేళ (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	ఎంపిక (opt & ~TCSASOFT) {
	స్థితి TCSANOW:
		తిరిగి (ioctl(fd, TIOCSETA, t));
	స్థితి TCSADRAIN:
		తిరిగి (ioctl(fd, TIOCSETAW, t));
	స్థితి TCSAFLUSH:
		తిరిగి (ioctl(fd, TIOCSETAF, t));
	అప్రమేయ:
		errno = EINVAL;
		తిరిగి (-1);
	}
}

పూర్ణాంకం tcsetpgrp(పూర్ణాంకం fd, pid_t pgrp)
{
	తిరిగి (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(స్థిరరాశి నిర్మాణం termios *t)
{
	తిరిగి (t->c_ospeed);
}

speed_t cfgetispeed(స్థిరరాశి నిర్మాణం termios *t)
{
	తిరిగి (t->c_ispeed);
}

పూర్ణాంకం
cfsetospeed(నిర్మాణం termios *t,పూర్ణాంకం వేగం)
{
	t->c_ospeed = వేగం;
	తిరిగి (0);
}

పూర్ణాంకం
cfsetispeed(నిర్మాణం termios *t, పూర్ణాంకం వేగం)
{
	t->c_ispeed = వేగం;
	తిరిగి (0);
}
#అయితే_ముగింపు /* HAVE_NEXT */
