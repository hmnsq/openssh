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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifndef HAVE_DAEMON

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <sys/stat.h>

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
daemon(ପୂର୍ଣ୍ଣସଂଖ୍ୟା nochdir, ପୂର୍ଣ୍ଣସଂଖ୍ୟା noclose)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;

	ବାଛ (fork()) {
	ସ୍ଥିତି -1:
		ଫେରନ୍ତୁ (-1);
	ସ୍ଥିତି 0:
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		_exit(0);
	}

	ଯଦି (setsid() == -1)
		ଫେରନ୍ତୁ (-1);

	ଯଦି (!nochdir)
		(ଶୂନ୍ୟ)chdir("/");

	ଯଦି (!noclose && (fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
		(ଶୂନ୍ୟ)dup2(fd, STDIN_FILENO);
		(ଶୂନ୍ୟ)dup2(fd, STDOUT_FILENO);
		(ଶୂନ୍ୟ)dup2(fd, STDERR_FILENO);
		ଯଦି (fd > 2)
			(ଶୂନ୍ୟ)close (fd);
	}
	ଫେରନ୍ତୁ (0);
}

#endif /* !HAVE_DAEMON */

