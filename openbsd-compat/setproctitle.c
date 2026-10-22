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

#ضمن "includes.h"

#ifndef HAVE_SETPROCTITLE

#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <unistd.h>
#ifdef HAVE_SYS_PSTAT_H
#ضمن <sys/pstat.h>
#endif
#ضمن <string.h>

#ضمن <vis.h>

#define SPT_NONE	0	/* don't use it at all */
#define SPT_PSTAT	1	/* use pstat(PSTAT_SETCMD, ...) */
#define SPT_REUSEARGV	2	/* cover argv with title information */

#ifndef SPT_TYPE
# define SPT_TYPE	SPT_NONE
#endif

#ifndef SPT_PADCHAR
# define SPT_PADCHAR	'\0'
#endif

#אם SPT_TYPE == SPT_REUSEARGV
ساكن حرف *argv_start = عدم;
ساكن size_t argv_env_len = 0;
#endif

#endif /* HAVE_SETPROCTITLE */

فراغ
compat_init_setproctitle(صحيح argc, حرف *argv[])
{
#אם !defined(HAVE_SETPROCTITLE) && \
    defined(SPT_TYPE) && SPT_TYPE == SPT_REUSEARGV
	خارجي حرف **environ;
	حرف *lastargv = عدم;
	حرف **envp = environ;
	صحيح i;

	/*
	 * NB: This assumes that argv has already been copied out of the
	 * way. This is true for sshd, but may not be true for other
	 * programs. Beware.
	 */

	אם (argc == 0 || argv[0] == عدم)
		החזר;

	/* Fail if we can't allocate room for the new environment */
	עבור (i = 0; envp[i] != عدم; i++)
		;
	אם ((environ = calloc(i + 1, حجم(*environ))) == عدم) {
		environ = envp;	/* put it back */
		החזר;
	}

	/*
	 * Find the last argv string or environment variable within
	 * our process memory area.
	 */
	עבור (i = 0; i < argc; i++) {
		אם (lastargv == عدم || lastargv + 1 == argv[i])
			lastargv = argv[i] + strlen(argv[i]);
	}
	עבור (i = 0; envp[i] != عدم; i++) {
		אם (lastargv + 1 == envp[i])
			lastargv = envp[i] + strlen(envp[i]);
	}

	argv[1] = عدم;
	argv_start = argv[0];
	argv_env_len = lastargv - argv[0] - 1;

	/*
	 * Copy environment
	 * XXX - will truncate env on strdup fail
	 */
	עבור (i = 0; envp[i] != عدم; i++)
		environ[i] = strdup(envp[i]);
	environ[i] = عدم;
#endif /* SPT_REUSEARGV */
}

#ifndef HAVE_SETPROCTITLE
فراغ
setproctitle(ثابت حرف *fmt, ...)
{
#אם SPT_TYPE != SPT_NONE
	va_list ap;
	حرف buf[1024], ptitle[1024];
	size_t len = 0;
	صحيح r;
	خارجي حرف *__progname;
#אם SPT_TYPE == SPT_PSTAT
	اتحاد pstun pst;
#endif

#אם SPT_TYPE == SPT_REUSEARGV
	אם (argv_env_len <= 0)
		החזר;
#endif

	strlcpy(buf, __progname, حجم(buf));

	r = -1;
	va_start(ap, fmt);
	אם (fmt != عدم) {
		len = strlcat(buf, ": ", حجم(buf));
		אם (len < حجم(buf))
			r = vsnprintf(buf + len, حجم(buf) - len , fmt, ap);
	}
	va_end(ap);
	אם (r == -1 || (size_t)r >= حجم(buf) - len)
		החזר;
	strnvis(ptitle, buf, حجم(ptitle),
	    VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL);

#אם SPT_TYPE == SPT_PSTAT
	pst.pst_command = ptitle;
	pstat(PSTAT_SETCMD, pst, strlen(ptitle), 0, 0);
#وإلاإذا SPT_TYPE == SPT_REUSEARGV
/*	debug("setproctitle: copy \"%s\" into len %d",
	    buf, argv_env_len); */
	len = strlcpy(argv_start, ptitle, argv_env_len);
	עבור(; len < argv_env_len; len++)
		argv_start[len] = SPT_PADCHAR;
#endif

#endif /* SPT_NONE */
}

#endif /* HAVE_SETPROCTITLE */
