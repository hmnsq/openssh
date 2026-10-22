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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_DAEMON

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FCNTL_H
# include <fcntl.h>
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_UNISTD_H
# include <unistd.h>
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
daemon(ಪೂರ್ಣಾಂಕ nochdir, ಪೂರ್ಣಾಂಕ noclose)
{
	ಪೂರ್ಣಾಂಕ fd;

	ಆಯ್ಕೆ (fork()) {
	ಸ್ಥಿತಿ -1:
		ಹಿಂತಿರುಗಿ (-1);
	ಸ್ಥಿತಿ 0:
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		_exit(0);
	}

	ಆದರೆ (setsid() == -1)
		ಹಿಂತಿರುಗಿ (-1);

	ಆದರೆ (!nochdir)
		(ಶೂನ್ಯ)chdir("/");

	ಆದರೆ (!noclose && (fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
		(ಶೂನ್ಯ)dup2(fd, STDIN_FILENO);
		(ಶೂನ್ಯ)dup2(fd, STDOUT_FILENO);
		(ಶೂನ್ಯ)dup2(fd, STDERR_FILENO);
		ಆದರೆ (fd > 2)
			(ಶೂನ್ಯ)close (fd);
	}
	ಹಿಂತಿರುಗಿ (0);
}

#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_DAEMON */

