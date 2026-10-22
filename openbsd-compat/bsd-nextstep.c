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
posix_wait(पूर्णाङ्क *status)
{
	सङ्घ wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	सचे (status)
		*status = (पूर्णाङ्क) statusp.w_status;

	पटिनिवत्त (wait_pid);
}

पूर्णाङ्क
tcgetattr(पूर्णाङ्क fd, संरचना termios *t)
{
	पटिनिवत्त (ioctl(fd, TIOCGETA, t));
}

पूर्णाङ्क
tcsetattr(पूर्णाङ्क fd, पूर्णाङ्क opt, ध्रुव संरचना termios *t)
{
	संरचना termios localterm;

	सचे (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	विकल्प (opt & ~TCSASOFT) {
	पक्ष TCSANOW:
		पटिनिवत्त (ioctl(fd, TIOCSETA, t));
	पक्ष TCSADRAIN:
		पटिनिवत्त (ioctl(fd, TIOCSETAW, t));
	पक्ष TCSAFLUSH:
		पटिनिवत्त (ioctl(fd, TIOCSETAF, t));
	स्वभाव:
		errno = EINVAL;
		पटिनिवत्त (-1);
	}
}

पूर्णाङ्क tcsetpgrp(पूर्णाङ्क fd, pid_t pgrp)
{
	पटिनिवत्त (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(ध्रुव संरचना termios *t)
{
	पटिनिवत्त (t->c_ospeed);
}

speed_t cfgetispeed(ध्रुव संरचना termios *t)
{
	पटिनिवत्त (t->c_ispeed);
}

पूर्णाङ्क
cfsetospeed(संरचना termios *t,पूर्णाङ्क speed)
{
	t->c_ospeed = speed;
	पटिनिवत्त (0);
}

पूर्णाङ्क
cfsetispeed(संरचना termios *t, पूर्णाङ्क speed)
{
	t->c_ispeed = speed;
	पटिनिवत्त (0);
}
#endif /* HAVE_NEXT */
