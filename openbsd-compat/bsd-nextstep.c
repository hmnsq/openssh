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

#അന്തര്ഭാവ "includes.h"

#ifdef HAVE_NEXT
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <sys/wait.h>
#അന്തര്ഭാവ "bsd-nextstep.h"

pid_t
posix_wait(പൂർണ്ണസംഖ്യ *status)
{
	സംഘം wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	എങ്കിൽ (status)
		*status = (പൂർണ്ണസംഖ്യ) statusp.w_status;

	തിരികെ (wait_pid);
}

പൂർണ്ണസംഖ്യ
tcgetattr(പൂർണ്ണസംഖ്യ fd, ഘടന termios *t)
{
	തിരികെ (ioctl(fd, TIOCGETA, t));
}

പൂർണ്ണസംഖ്യ
tcsetattr(പൂർണ്ണസംഖ്യ fd, പൂർണ്ണസംഖ്യ opt, സ്ഥിരം ഘടന termios *t)
{
	ഘടന termios localterm;

	എങ്കിൽ (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	തിരഞ്ഞെടുപ്പ് (opt & ~TCSASOFT) {
	അവസ്ഥ TCSANOW:
		തിരികെ (ioctl(fd, TIOCSETA, t));
	അവസ്ഥ TCSADRAIN:
		തിരികെ (ioctl(fd, TIOCSETAW, t));
	അവസ്ഥ TCSAFLUSH:
		തിരികെ (ioctl(fd, TIOCSETAF, t));
	സ്ഥിരസ്ഥിതി:
		errno = EINVAL;
		തിരികെ (-1);
	}
}

പൂർണ്ണസംഖ്യ tcsetpgrp(പൂർണ്ണസംഖ്യ fd, pid_t pgrp)
{
	തിരികെ (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(സ്ഥിരം ഘടന termios *t)
{
	തിരികെ (t->c_ospeed);
}

speed_t cfgetispeed(സ്ഥിരം ഘടന termios *t)
{
	തിരികെ (t->c_ispeed);
}

പൂർണ്ണസംഖ്യ
cfsetospeed(ഘടന termios *t,പൂർണ്ണസംഖ്യ speed)
{
	t->c_ospeed = speed;
	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
cfsetispeed(ഘടന termios *t, പൂർണ്ണസംഖ്യ speed)
{
	t->c_ispeed = speed;
	തിരികെ (0);
}
#endif /* HAVE_NEXT */
