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

#அந்தர்பாவ "includes.h"

#ifndef HAVE_SETPROCTITLE

#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <unistd.h>
#ifdef HAVE_SYS_PSTAT_H
#அந்தர்பாவ <sys/pstat.h>
#endif
#அந்தர்பாவ <string.h>

#அந்தர்பாவ <vis.h>

#define SPT_NONE	0	/* don't use it at all */
#define SPT_PSTAT	1	/* use pstat(PSTAT_SETCMD, ...) */
#define SPT_REUSEARGV	2	/* cover argv with title information */

#ifndef SPT_TYPE
# define SPT_TYPE	SPT_NONE
#endif

#ifndef SPT_PADCHAR
# define SPT_PADCHAR	'\0'
#endif

#எனில் SPT_TYPE == SPT_REUSEARGV
நிலையான எழுத்து *argv_start = வெற்று;
நிலையான size_t argv_env_len = 0;
#endif

#endif /* HAVE_SETPROCTITLE */

வெறுமை
compat_init_setproctitle(முழு argc, எழுத்து *argv[])
{
#எனில் !defined(HAVE_SETPROCTITLE) && \
    defined(SPT_TYPE) && SPT_TYPE == SPT_REUSEARGV
	வெளி எழுத்து **environ;
	எழுத்து *lastargv = வெற்று;
	எழுத்து **envp = environ;
	முழு i;

	/*
	 * NB: This assumes that argv has already been copied out of the
	 * way. This is true for sshd, but may not be true for other
	 * programs. Beware.
	 */

	எனில் (argc == 0 || argv[0] == வெற்று)
		திரும்பு;

	/* Fail if we can't allocate room for the new environment */
	க்கு (i = 0; envp[i] != வெற்று; i++)
		;
	எனில் ((environ = calloc(i + 1, அளவு(*environ))) == வெற்று) {
		environ = envp;	/* put it back */
		திரும்பு;
	}

	/*
	 * Find the last argv string or environment variable within
	 * our process memory area.
	 */
	க்கு (i = 0; i < argc; i++) {
		எனில் (lastargv == வெற்று || lastargv + 1 == argv[i])
			lastargv = argv[i] + strlen(argv[i]);
	}
	க்கு (i = 0; envp[i] != வெற்று; i++) {
		எனில் (lastargv + 1 == envp[i])
			lastargv = envp[i] + strlen(envp[i]);
	}

	argv[1] = வெற்று;
	argv_start = argv[0];
	argv_env_len = lastargv - argv[0] - 1;

	/*
	 * Copy environment
	 * XXX - will truncate env on strdup fail
	 */
	க்கு (i = 0; envp[i] != வெற்று; i++)
		environ[i] = strdup(envp[i]);
	environ[i] = வெற்று;
#endif /* SPT_REUSEARGV */
}

#ifndef HAVE_SETPROCTITLE
வெறுமை
setproctitle(மாறிலி எழுத்து *fmt, ...)
{
#எனில் SPT_TYPE != SPT_NONE
	va_list ap;
	எழுத்து buf[1024], ptitle[1024];
	size_t len = 0;
	முழு r;
	வெளி எழுத்து *__progname;
#எனில் SPT_TYPE == SPT_PSTAT
	ஒன்றிப்பு pstun pst;
#endif

#எனில் SPT_TYPE == SPT_REUSEARGV
	எனில் (argv_env_len <= 0)
		திரும்பு;
#endif

	strlcpy(buf, __progname, அளவு(buf));

	r = -1;
	va_start(ap, fmt);
	எனில் (fmt != வெற்று) {
		len = strlcat(buf, ": ", அளவு(buf));
		எனில் (len < அளவு(buf))
			r = vsnprintf(buf + len, அளவு(buf) - len , fmt, ap);
	}
	va_end(ap);
	எனில் (r == -1 || (size_t)r >= அளவு(buf) - len)
		திரும்பு;
	strnvis(ptitle, buf, அளவு(ptitle),
	    VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL);

#எனில் SPT_TYPE == SPT_PSTAT
	pst.pst_command = ptitle;
	pstat(PSTAT_SETCMD, pst, strlen(ptitle), 0, 0);
#அல்லதெனில் SPT_TYPE == SPT_REUSEARGV
/*	debug("setproctitle: copy \"%s\" into len %d",
	    buf, argv_env_len); */
	len = strlcpy(argv_start, ptitle, argv_env_len);
	க்கு(; len < argv_env_len; len++)
		argv_start[len] = SPT_PADCHAR;
#endif

#endif /* SPT_NONE */
}

#endif /* HAVE_SETPROCTITLE */
