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

#অন্তর্ভাব "includes.h"

#ifdef HAVE_পরবর্তী
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <sys/wait.h>
#অন্তর্ভাব "bsd-nextstep.h"

pid_t
posix_wait(পূর্ণসংখ্যা *status)
{
	সংঘ wait statusp;
	pid_t wait_pid;

	#undef wait			/* Use NeXT's wait() function */
	wait_pid = wait(&statusp);
	যদি (status)
		*status = (পূর্ণসংখ্যা) statusp.w_status;

	ফেরত (wait_pid);
}

পূর্ণসংখ্যা
tcgetattr(পূর্ণসংখ্যা fd, কাঠামো termios *t)
{
	ফেরত (ioctl(fd, TIOCGETA, t));
}

পূর্ণসংখ্যা
tcsetattr(পূর্ণসংখ্যা fd, পূর্ণসংখ্যা opt, ধ্রুবক কাঠামো termios *t)
{
	কাঠামো termios localterm;

	যদি (opt & TCSASOFT) {
		localterm = *t;
		localterm.c_cflag |= CIGNORE;
		t = &localterm;
	}
	নির্বাচন (opt & ~TCSASOFT) {
	ক্ষেত্র TCSANOW:
		ফেরত (ioctl(fd, TIOCSETA, t));
	ক্ষেত্র TCSADRAIN:
		ফেরত (ioctl(fd, TIOCSETAW, t));
	ক্ষেত্র TCSAFLUSH:
		ফেরত (ioctl(fd, TIOCSETAF, t));
	পূর্বনির্ধারিত:
		errno = EINVAL;
		ফেরত (-1);
	}
}

পূর্ণসংখ্যা tcsetpgrp(পূর্ণসংখ্যা fd, pid_t pgrp)
{
	ফেরত (ioctl(fd, TIOCSPGRP, &pgrp));
}

speed_t cfgetospeed(ধ্রুবক কাঠামো termios *t)
{
	ফেরত (t->c_ospeed);
}

speed_t cfgetispeed(ধ্রুবক কাঠামো termios *t)
{
	ফেরত (t->c_ispeed);
}

পূর্ণসংখ্যা
cfsetospeed(কাঠামো termios *t,পূর্ণসংখ্যা speed)
{
	t->c_ospeed = speed;
	ফেরত (0);
}

পূর্ণসংখ্যা
cfsetispeed(কাঠামো termios *t, পূর্ণসংখ্যা speed)
{
	t->c_ispeed = speed;
	ফেরত (0);
}
#endif /* HAVE_NEXT */
