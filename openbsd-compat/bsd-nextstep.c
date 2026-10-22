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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef HAVE_NEXT
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ "bsd-nextstep.h"

pid_t
posix_wait(ಪೂರ್ಣಾಙ್ಕ *status)
{
	ಸಙ್ಘ wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	ಯದಿ (status)
		*status = (ಪೂರ್ಣಾಙ್ಕ) statusp.w_status;

	ಪ್ರತ್ಯಾಗಮ (wait_pid);
}

ಪೂರ್ಣಾಙ್ಕ
tcgetattr(ಪೂರ್ಣಾಙ್ಕ fd, ಸಂರಚನಾ termios *t)
{
	ಪ್ರತ್ಯಾಗಮ (ioctl(fd, TIOCGETA, t));
}

ಪೂರ್ಣಾಙ್ಕ
tcsetattr(ಪೂರ್ಣಾಙ್ಕ fd, ಪೂರ್ಣಾಙ್ಕ opt, ಧ್ರುವ ಸಂರಚನಾ termios *t)
{
	ಸಂರಚನಾ termios localterm;

	ಯದಿ (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	ವಿಕಲ್ಪ (opt & ~TCSASOFT) {
	ಪಕ್ಷ TCSANOW:
		ಪ್ರತ್ಯಾಗಮ (ioctl(fd, TIOCSETA, t));
	ಪಕ್ಷ TCSADRAIN:
		ಪ್ರತ್ಯಾಗಮ (ioctl(fd, TIOCSETAW, t));
	ಪಕ್ಷ TCSAFLUSH:
		ಪ್ರತ್ಯಾಗಮ (ioctl(fd, TIOCSETAF, t));
	ಸ್ವಭಾವ:
		errno = EINVAL;
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
}

ಪೂರ್ಣಾಙ್ಕ tcsetpgrp(ಪೂರ್ಣಾಙ್ಕ fd, pid_t pgrp)
{
	ಪ್ರತ್ಯಾಗಮ (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(ಧ್ರುವ ಸಂರಚನಾ termios *t)
{
	ಪ್ರತ್ಯಾಗಮ (t->c_ospeed);
}

speed_t cfgetispeed(ಧ್ರುವ ಸಂರಚನಾ termios *t)
{
	ಪ್ರತ್ಯಾಗಮ (t->c_ispeed);
}

ಪೂರ್ಣಾಙ್ಕ
cfsetospeed(ಸಂರಚನಾ termios *t,ಪೂರ್ಣಾಙ್ಕ speed)
{
	t->c_ospeed = speed;
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
cfsetispeed(ಸಂರಚನಾ termios *t, ಪೂರ್ಣಾಙ್ಕ speed)
{
	t->c_ispeed = speed;
	ಪ್ರತ್ಯಾಗಮ (0);
}
#endif /* HAVE_NEXT */
