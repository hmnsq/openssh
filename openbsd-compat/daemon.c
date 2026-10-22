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

#समावेश "includes.h"

#अगर_अघोषित HAVE_DAEMON

#समावेश <sys/types.h>

#समावेश <sys/stat.h>

#अगर_घोषित HAVE_FCNTL_H
# include <fcntl.h>
#पूर्ण_अगर

#अगर_घोषित HAVE_UNISTD_H
# include <unistd.h>
#पूर्ण_अगर

पूर्णांक
daemon(पूर्णांक nochdir, पूर्णांक noclose)
{
	पूर्णांक fd;

	चयन (विभाजन()) {
	हाल -1:
		वापस (-1);
	हाल 0:
		अवरोध;
	शेष:
		_निकास(0);
	}

	अगर (setsid() == -1)
		वापस (-1);

	अगर (!nochdir)
		(व्योम)स_बदलो("/");

	अगर (!noclose && (fd = खोलो(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
		(व्योम)dup2(fd, STDIN_FILENO);
		(व्योम)dup2(fd, STDOUT_FILENO);
		(व्योम)dup2(fd, STDERR_FILENO);
		अगर (fd > 2)
			(व्योम)बंद (fd);
	}
	वापस (0);
}

#पूर्ण_अगर /* !HAVE_DAEMON */

