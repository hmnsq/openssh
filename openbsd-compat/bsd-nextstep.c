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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ಮುಂದಿನ
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ "bsd-nextstep.h"

pid_t
posix_wait(ಪೂರ್ಣಾಂಕ *ಸ್ಥಿತಿ_2)
{
	ಒಕ್ಕೂಟ wait statusp;
	pid_t wait_pid;

	#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	ಆದರೆ (ಸ್ಥಿತಿ_2)
		*ಸ್ಥಿತಿ_2 = (ಪೂರ್ಣಾಂಕ) statusp.w_ಸ್ಥಿತಿ;

	ಹಿಂತಿರುಗಿ (wait_pid);
}

ಪೂರ್ಣಾಂಕ
tcgetattr(ಪೂರ್ಣಾಂಕ fd, ರಚನೆ termios *t)
{
	ಹಿಂತಿರುಗಿ (ioctl(fd, TIOCGETA, t));
}

ಪೂರ್ಣಾಂಕ
tcsetattr(ಪೂರ್ಣಾಂಕ fd, ಪೂರ್ಣಾಂಕ opt, ಸ್ಥಿರಾಂಕ ರಚನೆ termios *t)
{
	ರಚನೆ termios localterm;

	ಆದರೆ (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	ಆಯ್ಕೆ (opt & ~TCSASOFT) {
	ಸ್ಥಿತಿ TCSANOW:
		ಹಿಂತಿರುಗಿ (ioctl(fd, TIOCSETA, t));
	ಸ್ಥಿತಿ TCSADRAIN:
		ಹಿಂತಿರುಗಿ (ioctl(fd, TIOCSETAW, t));
	ಸ್ಥಿತಿ TCSAFLUSH:
		ಹಿಂತಿರುಗಿ (ioctl(fd, TIOCSETAF, t));
	ಪೂರ್ವನಿಯೋಜಿತ:
		errno = EINVAL;
		ಹಿಂತಿರುಗಿ (-1);
	}
}

ಪೂರ್ಣಾಂಕ tcsetpgrp(ಪೂರ್ಣಾಂಕ fd, pid_t pgrp)
{
	ಹಿಂತಿರುಗಿ (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(ಸ್ಥಿರಾಂಕ ರಚನೆ termios *t)
{
	ಹಿಂತಿರುಗಿ (t->c_ospeed);
}

speed_t cfgetispeed(ಸ್ಥಿರಾಂಕ ರಚನೆ termios *t)
{
	ಹಿಂತಿರುಗಿ (t->c_ispeed);
}

ಪೂರ್ಣಾಂಕ
cfsetospeed(ರಚನೆ termios *t,ಪೂರ್ಣಾಂಕ ವೇಗ)
{
	t->c_ospeed = ವೇಗ;
	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
cfsetispeed(ರಚನೆ termios *t, ಪೂರ್ಣಾಂಕ ವೇಗ)
{
	t->c_ispeed = ವೇಗ;
	ಹಿಂತಿರುಗಿ (0);
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_NEXT */
