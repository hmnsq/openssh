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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ਅਗਲਾ
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "bsd-nextstep.h"

pid_t
posix_wait(ਪੂਰਨ *ਸਥਿਤੀ)
{
	ਸੰਘ wait statusp;
	pid_t wait_pid;

	#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	ਜੇ (ਸਥਿਤੀ)
		*ਸਥਿਤੀ = (ਪੂਰਨ) statusp.w_ਸਥਿਤੀ;

	ਵਾਪਸ (wait_pid);
}

ਪੂਰਨ
tcgetattr(ਪੂਰਨ fd, ਬਣਤਰ termios *t)
{
	ਵਾਪਸ (ioctl(fd, TIOCGETA, t));
}

ਪੂਰਨ
tcsetattr(ਪੂਰਨ fd, ਪੂਰਨ opt, ਅਚਲ ਬਣਤਰ termios *t)
{
	ਬਣਤਰ termios localterm;

	ਜੇ (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	ਚੋਣ (opt & ~TCSASOFT) {
	ਹਾਲਤ TCSANOW:
		ਵਾਪਸ (ioctl(fd, TIOCSETA, t));
	ਹਾਲਤ TCSADRAIN:
		ਵਾਪਸ (ioctl(fd, TIOCSETAW, t));
	ਹਾਲਤ TCSAFLUSH:
		ਵਾਪਸ (ioctl(fd, TIOCSETAF, t));
	ਮੂਲ:
		errno = EINVAL;
		ਵਾਪਸ (-1);
	}
}

ਪੂਰਨ tcsetpgrp(ਪੂਰਨ fd, pid_t pgrp)
{
	ਵਾਪਸ (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(ਅਚਲ ਬਣਤਰ termios *t)
{
	ਵਾਪਸ (t->c_ospeed);
}

speed_t cfgetispeed(ਅਚਲ ਬਣਤਰ termios *t)
{
	ਵਾਪਸ (t->c_ispeed);
}

ਪੂਰਨ
cfsetospeed(ਬਣਤਰ termios *t,ਪੂਰਨ ਰਫਤਾਰ)
{
	t->c_ospeed = ਰਫਤਾਰ;
	ਵਾਪਸ (0);
}

ਪੂਰਨ
cfsetispeed(ਬਣਤਰ termios *t, ਪੂਰਨ ਰਫਤਾਰ)
{
	t->c_ispeed = ਰਫਤਾਰ;
	ਵਾਪਸ (0);
}
#ਜੇ_ਅੰਤ /* HAVE_NEXT */
