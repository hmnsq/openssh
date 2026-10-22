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

#அந்தர்பாவ "includes.h"

#ifdef HAVE_NEXT
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <sys/wait.h>
#அந்தர்பாவ "bsd-nextstep.h"

pid_t
posix_wait(முழு *status)
{
	ஒன்றிப்பு wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	எனில் (status)
		*status = (முழு) statusp.w_status;

	திரும்பு (wait_pid);
}

முழு
tcgetattr(முழு fd, கட்டமைப்பு termios *t)
{
	திரும்பு (ioctl(fd, TIOCGETA, t));
}

முழு
tcsetattr(முழு fd, முழு opt, மாறிலி கட்டமைப்பு termios *t)
{
	கட்டமைப்பு termios localterm;

	எனில் (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	தேர்வு (opt & ~TCSASOFT) {
	நிலை TCSANOW:
		திரும்பு (ioctl(fd, TIOCSETA, t));
	நிலை TCSADRAIN:
		திரும்பு (ioctl(fd, TIOCSETAW, t));
	நிலை TCSAFLUSH:
		திரும்பு (ioctl(fd, TIOCSETAF, t));
	இயல்பு:
		errno = EINVAL;
		திரும்பு (-1);
	}
}

முழு tcsetpgrp(முழு fd, pid_t pgrp)
{
	திரும்பு (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(மாறிலி கட்டமைப்பு termios *t)
{
	திரும்பு (t->c_ospeed);
}

speed_t cfgetispeed(மாறிலி கட்டமைப்பு termios *t)
{
	திரும்பு (t->c_ispeed);
}

முழு
cfsetospeed(கட்டமைப்பு termios *t,முழு speed)
{
	t->c_ospeed = speed;
	திரும்பு (0);
}

முழு
cfsetispeed(கட்டமைப்பு termios *t, முழு speed)
{
	t->c_ispeed = speed;
	திரும்பு (0);
}
#endif /* HAVE_NEXT */
