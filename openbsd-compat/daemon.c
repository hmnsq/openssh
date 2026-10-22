/*	$OpenBSD: daemon.c,v 1.6 2005/08/08 08:05:33 espie Exp $ */
/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: lib/libc/gen/daemon.c */

#অন্তর্ভাব "includes.h"

#ifndef HAVE_DAEMON

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <sys/stat.h>

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

পূর্ণাঙ্ক
daemon(পূর্ণাঙ্ক nochdir, পূর্ণাঙ্ক noclose)
{
	পূর্ণাঙ্ক fd;

	বিকল্প (fork()) {
	পক্ষ -1:
		প্রত্যাগম (-1);
	পক্ষ 0:
		ভঙ্গ;
	স্বভাব:
		_exit(0);
	}

	যদি (setsid() == -1)
		প্রত্যাগম (-1);

	যদি (!nochdir)
		(শূন্য)chdir("/");

	যদি (!noclose && (fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
		(শূন্য)dup2(fd, STDIN_FILENO);
		(শূন্য)dup2(fd, STDOUT_FILENO);
		(শূন্য)dup2(fd, STDERR_FILENO);
		যদি (fd > 2)
			(শূন্য)close (fd);
	}
	প্রত্যাগম (0);
}

#endif /* !HAVE_DAEMON */

