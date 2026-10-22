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

#अन्तर्भाव "includes.h"

#ifdef HAVE_NEXT
#अन्तर्भाव <errno.h>
#अन्तर्भाव <sys/wait.h>
#अन्तर्भाव "bsd-nextstep.h"

pid_t
posix_wait(पूर्णांक *status)
{
	संघ रुको statusp;
	pid_t wait_pid;

	#undef रुको			/* Use NeXT's wait() function */
	wait_pid = रुको(&statusp);
	जर (status)
		*status = (पूर्णांक) statusp.w_status;

	परत (wait_pid);
}

पूर्णांक
tcgetattr(पूर्णांक fd, संरचना termios *t)
{
	परत (ioctl(fd, TIOCGETA, t));
}

पूर्णांक
tcsetattr(पूर्णांक fd, पूर्णांक opt, स्थिरांक संरचना termios *t)
{
	संरचना termios localterm;

	जर (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	निवड (opt & ~TCSASOFT) {
	स्थिती TCSANOW:
		परत (ioctl(fd, TIOCSETA, t));
	स्थिती TCSADRAIN:
		परत (ioctl(fd, TIOCSETAW, t));
	स्थिती TCSAFLUSH:
		परत (ioctl(fd, TIOCSETAF, t));
	पूर्वनिर्धारित:
		त्रुटि_सं = EINVAL;
		परत (-1);
	}
}

पूर्णांक tcsetpgrp(पूर्णांक fd, pid_t pgrp)
{
	परत (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(स्थिरांक संरचना termios *t)
{
	परत (t->c_ospeed);
}

speed_t cfgetispeed(स्थिरांक संरचना termios *t)
{
	परत (t->c_ispeed);
}

पूर्णांक
cfsetospeed(संरचना termios *t,पूर्णांक speed)
{
	t->c_ospeed = speed;
	परत (0);
}

पूर्णांक
cfsetispeed(संरचना termios *t, पूर्णांक speed)
{
	t->c_ispeed = speed;
	परत (0);
}
#endif /* HAVE_NEXT */
