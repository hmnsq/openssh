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

#അന്തര്ഭാവ "includes.h"

#ifndef HAVE_DAEMON

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <sys/stat.h>

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

പൂർണ്ണസംഖ്യ
daemon(പൂർണ്ണസംഖ്യ nochdir, പൂർണ്ണസംഖ്യ noclose)
{
	പൂർണ്ണസംഖ്യ fd;

	തിരഞ്ഞെടുപ്പ് (fork()) {
	അവസ്ഥ -1:
		തിരികെ (-1);
	അവസ്ഥ 0:
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		_exit(0);
	}

	എങ്കിൽ (setsid() == -1)
		തിരികെ (-1);

	എങ്കിൽ (!nochdir)
		(ശൂന്യം)chdir("/");

	എങ്കിൽ (!noclose && (fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
		(ശൂന്യം)dup2(fd, STDIN_FILENO);
		(ശൂന്യം)dup2(fd, STDOUT_FILENO);
		(ശൂന്യം)dup2(fd, STDERR_FILENO);
		എങ്കിൽ (fd > 2)
			(ശൂന്യം)close (fd);
	}
	തിരികെ (0);
}

#endif /* !HAVE_DAEMON */

