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

#అన్తర్భావ "includes.h"

#నిర్వచితం_కాకపోతే HAVE_DAEMON

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <sys/stat.h>

#నిర్వచితమైతే HAVE_FCNTL_H
# include <fcntl.h>
#అయితే_ముగింపు

#నిర్వచితమైతే HAVE_UNISTD_H
# include <unistd.h>
#అయితే_ముగింపు

పూర్ణాంకం
daemon(పూర్ణాంకం nochdir, పూర్ణాంకం noclose)
{
	పూర్ణాంకం fd;

	ఎంపిక (fork()) {
	స్థితి -1:
		తిరిగి (-1);
	స్థితి 0:
		ఆపు;
	అప్రమేయ:
		_exit(0);
	}

	ఒకవేళ (setsid() == -1)
		తిరిగి (-1);

	ఒకవేళ (!nochdir)
		(శూన్య)chdir("/");

	ఒకవేళ (!noclose && (fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
		(శూన్య)dup2(fd, STDIN_FILENO);
		(శూన్య)dup2(fd, STDOUT_FILENO);
		(శూన్య)dup2(fd, STDERR_FILENO);
		ఒకవేళ (fd > 2)
			(శూన్య)close (fd);
	}
	తిరిగి (0);
}

#అయితే_ముగింపు /* !HAVE_DAEMON */

