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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef HAVE_NEXT
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>
#ଅନ୍ତର୍ଭାଵ "bsd-nextstep.h"

pid_t
posix_wait(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *status)
{
	ସଂଘ wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	ଯଦି (status)
		*status = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା) statusp.w_status;

	ଫେରନ୍ତୁ (wait_pid);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
tcgetattr(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ସଂରଚନା termios *t)
{
	ଫେରନ୍ତୁ (ioctl(fd, TIOCGETA, t));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
tcsetattr(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା opt, ଅଚଳ ସଂରଚନା termios *t)
{
	ସଂରଚନା termios localterm;

	ଯଦି (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	ବାଛ (opt & ~TCSASOFT) {
	ସ୍ଥିତି TCSANOW:
		ଫେରନ୍ତୁ (ioctl(fd, TIOCSETA, t));
	ସ୍ଥିତି TCSADRAIN:
		ଫେରନ୍ତୁ (ioctl(fd, TIOCSETAW, t));
	ସ୍ଥିତି TCSAFLUSH:
		ଫେରନ୍ତୁ (ioctl(fd, TIOCSETAF, t));
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		errno = EINVAL;
		ଫେରନ୍ତୁ (-1);
	}
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା tcsetpgrp(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, pid_t pgrp)
{
	ଫେରନ୍ତୁ (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(ଅଚଳ ସଂରଚନା termios *t)
{
	ଫେରନ୍ତୁ (t->c_ospeed);
}

speed_t cfgetispeed(ଅଚଳ ସଂରଚନା termios *t)
{
	ଫେରନ୍ତୁ (t->c_ispeed);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cfsetospeed(ସଂରଚନା termios *t,ପୂର୍ଣ୍ଣସଂଖ୍ୟା speed)
{
	t->c_ospeed = speed;
	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cfsetispeed(ସଂରଚନା termios *t, ପୂର୍ଣ୍ଣସଂଖ୍ୟା speed)
{
	t->c_ispeed = speed;
	ଫେରନ୍ତୁ (0);
}
#endif /* HAVE_NEXT */
