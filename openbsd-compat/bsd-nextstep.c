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

#समावेश "includes.h"

#अगर_घोषित HAVE_अग्र
#समावेश <errno.h>
#समावेश <sys/wait.h>
#समावेश "bsd-nextstep.h"

pid_t
posix_wait(पूर्णांक *status)
{
	जोड़ रुको statusp;
	pid_t wait_pid;

	#अघोषित रुको			/* Use NeXT's wait() function */
	wait_pid = रुको(&statusp);
	अगर (status)
		*status = (पूर्णांक) statusp.w_status;

	वापस (wait_pid);
}

पूर्णांक
tcgetattr(पूर्णांक fd, काष्ठा termios *t)
{
	वापस (ioctl(fd, TIOCGETA, t));
}

पूर्णांक
tcsetattr(पूर्णांक fd, पूर्णांक opt, स्थिर काष्ठा termios *t)
{
	काष्ठा termios localterm;

	अगर (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	चयन (opt & ~TCSASOFT) {
	हाल TCSANOW:
		वापस (ioctl(fd, TIOCSETA, t));
	हाल TCSADRAIN:
		वापस (ioctl(fd, TIOCSETAW, t));
	हाल TCSAFLUSH:
		वापस (ioctl(fd, TIOCSETAF, t));
	शेष:
		त्रुटि_सं = EINVAL;
		वापस (-1);
	}
}

पूर्णांक tcsetpgrp(पूर्णांक fd, pid_t pgrp)
{
	वापस (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(स्थिर काष्ठा termios *t)
{
	वापस (t->c_ospeed);
}

speed_t cfgetispeed(स्थिर काष्ठा termios *t)
{
	वापस (t->c_ispeed);
}

पूर्णांक
cfsetospeed(काष्ठा termios *t,पूर्णांक speed)
{
	t->c_ospeed = speed;
	वापस (0);
}

पूर्णांक
cfsetispeed(काष्ठा termios *t, पूर्णांक speed)
{
	t->c_ispeed = speed;
	वापस (0);
}
#पूर्ण_अगर /* HAVE_NEXT */
