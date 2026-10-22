/* Based on conf.c from UCB sendmail 8.8.8 */

/*
 * Copyright 2003 Damien Miller
 * Copyright (c) 1983, 1995-1997 Eric P. Allman
 * Copyright (c) 1988, 1993
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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifndef HAVE_SETPROCTITLE

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ifdef HAVE_SYS_PSTAT_H
#ಅನ್ತರ್ಭಾವ <sys/pstat.h>
#endif
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ <vis.h>

#define SPT_NONE	0	/* don't use it at all */
#define SPT_PSTAT	1	/* use pstat(PSTAT_SETCMD, ...) */
#define SPT_REUSEARGV	2	/* cover argv with title information */

#ifndef SPT_TYPE
# define SPT_TYPE	SPT_NONE
#endif

#ifndef SPT_PADCHAR
# define SPT_PADCHAR	'\0'
#endif

#ಯದಿ SPT_TYPE == SPT_REUSEARGV
ಸ್ಥಿರ ವರ್ಣ *argv_start = ರಿಕ್ತ;
ಸ್ಥಿರ size_t argv_env_len = 0;
#endif

#endif /* HAVE_SETPROCTITLE */

ಶೂನ್ಯ
compat_init_setproctitle(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ *argv[])
{
#ಯದಿ !defined(HAVE_SETPROCTITLE) && \
    defined(SPT_TYPE) && SPT_TYPE == SPT_REUSEARGV
	ಬಾಹ್ಯ ವರ್ಣ **environ;
	ವರ್ಣ *lastargv = ರಿಕ್ತ;
	ವರ್ಣ **envp = environ;
	ಪೂರ್ಣಾಙ್ಕ i;

	/*
	 * NB: This assumes that argv has already been copied out of the
	 * way. This is true for sshd, but may not be true for other
	 * programs. Beware.
	 */

	ಯದಿ (argc == 0 || argv[0] == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	/* Fail if we can't allocate room for the new environment */
	ಪ್ರತಿ (i = 0; envp[i] != ರಿಕ್ತ; i++)
		;
	ಯದಿ ((environ = calloc(i + 1, ಪರಿಮಾಣ(*environ))) == ರಿಕ್ತ) {
		environ = envp;	/* put it back */
		ಪ್ರತ್ಯಾಗಮ;
	}

	/*
	 * Find the last argv string or environment variable within
	 * our process memory area.
	 */
	ಪ್ರತಿ (i = 0; i < argc; i++) {
		ಯದಿ (lastargv == ರಿಕ್ತ || lastargv + 1 == argv[i])
			lastargv = argv[i] + strlen(argv[i]);
	}
	ಪ್ರತಿ (i = 0; envp[i] != ರಿಕ್ತ; i++) {
		ಯದಿ (lastargv + 1 == envp[i])
			lastargv = envp[i] + strlen(envp[i]);
	}

	argv[1] = ರಿಕ್ತ;
	argv_start = argv[0];
	argv_env_len = lastargv - argv[0] - 1;

	/*
	 * Copy environment
	 * XXX - will truncate env on strdup fail
	 */
	ಪ್ರತಿ (i = 0; envp[i] != ರಿಕ್ತ; i++)
		environ[i] = strdup(envp[i]);
	environ[i] = ರಿಕ್ತ;
#endif /* SPT_REUSEARGV */
}

#ifndef HAVE_SETPROCTITLE
ಶೂನ್ಯ
setproctitle(ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
#ಯದಿ SPT_TYPE != SPT_NONE
	va_list ap;
	ವರ್ಣ buf[1024], ptitle[1024];
	size_t len = 0;
	ಪೂರ್ಣಾಙ್ಕ r;
	ಬಾಹ್ಯ ವರ್ಣ *__progname;
#ಯದಿ SPT_TYPE == SPT_PSTAT
	ಸಙ್ಘ pstun pst;
#endif

#ಯದಿ SPT_TYPE == SPT_REUSEARGV
	ಯದಿ (argv_env_len <= 0)
		ಪ್ರತ್ಯಾಗಮ;
#endif

	strlcpy(buf, __progname, ಪರಿಮಾಣ(buf));

	r = -1;
	va_start(ap, fmt);
	ಯದಿ (fmt != ರಿಕ್ತ) {
		len = strlcat(buf, ": ", ಪರಿಮಾಣ(buf));
		ಯದಿ (len < ಪರಿಮಾಣ(buf))
			r = vsnprintf(buf + len, ಪರಿಮಾಣ(buf) - len , fmt, ap);
	}
	va_end(ap);
	ಯದಿ (r == -1 || (size_t)r >= ಪರಿಮಾಣ(buf) - len)
		ಪ್ರತ್ಯಾಗಮ;
	strnvis(ptitle, buf, ಪರಿಮಾಣ(ptitle),
	    VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL);

#ಯದಿ SPT_TYPE == SPT_PSTAT
	pst.pst_command = ptitle;
	pstat(PSTAT_SETCMD, pst, strlen(ptitle), 0, 0);
#ನೋಚೇದ್ಯದಿ SPT_TYPE == SPT_REUSEARGV
/*	debug("setproctitle: copy \"%s\" into len %d",
	    buf, argv_env_len); */
	len = strlcpy(argv_start, ptitle, argv_env_len);
	ಪ್ರತಿ(; len < argv_env_len; len++)
		argv_start[len] = SPT_PADCHAR;
#endif

#endif /* SPT_NONE */
}

#endif /* HAVE_SETPROCTITLE */
