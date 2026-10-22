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

#అన్తర్భావ "includes.h"

#నిర్వచితం_కాకపోతే HAVE_SETPROCTITLE

#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <unistd.h>
#నిర్వచితమైతే HAVE_SYS_PSTAT_H
#అన్తర్భావ <sys/pstat.h>
#అయితే_ముగింపు
#అన్తర్భావ <string.h>

#అన్తర్భావ <vis.h>

#నిర్వచించు SPT_NONE	0	/* don't use it at all */
#నిర్వచించు SPT_PSTAT	1	/* use pstat(PSTAT_SETCMD, ...) */
#నిర్వచించు SPT_REUSEARGV	2	/* cover argv with title information */

#నిర్వచితం_కాకపోతే SPT_TYPE
# define SPT_TYPE	SPT_NONE
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే SPT_PADCHAR
# define SPT_PADCHAR	'\0'
#అయితే_ముగింపు

#ఒకవేళ SPT_TYPE == SPT_REUSEARGV
స్థిర అక్షరం *argv_ప్రారంభం = ఖాళీ;
స్థిర కొలత_t argv_env_len = 0;
#అయితే_ముగింపు

#అయితే_ముగింపు /* HAVE_SETPROCTITLE */

శూన్య
compat_init_setproctitle(పూర్ణాంకం argc, అక్షరం *argv[])
{
#ఒకవేళ !defined(HAVE_SETPROCTITLE) && \
    defined(SPT_TYPE) && SPT_TYPE == SPT_REUSEARGV
	బాహ్య అక్షరం **environ;
	అక్షరం *lastargv = ఖాళీ;
	అక్షరం **envp = environ;
	పూర్ణాంకం i;

	/*
	 * NB: This assumes that argv has already been copied out of the
	 * way. This is true for sshd, but may not be true for other
	 * programs. Beware.
	 */

	ఒకవేళ (argc == 0 || argv[0] == ఖాళీ)
		తిరిగి;

	/* Fail if we can't allocate room for the new environment */
	కొరకు (i = 0; envp[i] != ఖాళీ; i++)
		;
	ఒకవేళ ((environ = సున్నా_జ్ఞాపకం_ఇవ్వు(i + 1, పరిమాణం(*environ))) == ఖాళీ) {
		environ = envp;	/* put it back */
		తిరిగి;
	}

	/*
	 * Find the last argv string or environment variable within
	 * our process memory area.
	 */
	కొరకు (i = 0; i < argc; i++) {
		ఒకవేళ (lastargv == ఖాళీ || lastargv + 1 == argv[i])
			lastargv = argv[i] + అక్షరశ్రేణి_పొడవు(argv[i]);
	}
	కొరకు (i = 0; envp[i] != ఖాళీ; i++) {
		ఒకవేళ (lastargv + 1 == envp[i])
			lastargv = envp[i] + అక్షరశ్రేణి_పొడవు(envp[i]);
	}

	argv[1] = ఖాళీ;
	argv_ప్రారంభం = argv[0];
	argv_env_len = lastargv - argv[0] - 1;

	/*
	 * Copy environment
	 * XXX - will truncate env on strdup fail
	 */
	కొరకు (i = 0; envp[i] != ఖాళీ; i++)
		environ[i] = strdup(envp[i]);
	environ[i] = ఖాళీ;
#అయితే_ముగింపు /* SPT_REUSEARGV */
}

#నిర్వచితం_కాకపోతే HAVE_SETPROCTITLE
శూన్య
setproctitle(స్థిరరాశి అక్షరం *fmt, ...)
{
#ఒకవేళ SPT_TYPE != SPT_NONE
	va_list ap;
	అక్షరం buf[1024], ptitle[1024];
	కొలత_t len = 0;
	పూర్ణాంకం r;
	బాహ్య అక్షరం *__progname;
#ఒకవేళ SPT_TYPE == SPT_PSTAT
	సంఘం pstun pst;
#అయితే_ముగింపు

#ఒకవేళ SPT_TYPE == SPT_REUSEARGV
	ఒకవేళ (argv_env_len <= 0)
		తిరిగి;
#అయితే_ముగింపు

	strlcpy(buf, __progname, పరిమాణం(buf));

	r = -1;
	va_start(ap, fmt);
	ఒకవేళ (fmt != ఖాళీ) {
		len = strlcat(buf, ": ", పరిమాణం(buf));
		ఒకవేళ (len < పరిమాణం(buf))
			r = vsnprintf(buf + len, పరిమాణం(buf) - len , fmt, ap);
	}
	va_end(ap);
	ఒకవేళ (r == -1 || (కొలత_t)r >= పరిమాణం(buf) - len)
		తిరిగి;
	strnvis(ptitle, buf, పరిమాణం(ptitle),
	    VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL);

#ఒకవేళ SPT_TYPE == SPT_PSTAT
	pst.pst_command = ptitle;
	pstat(PSTAT_SETCMD, pst, అక్షరశ్రేణి_పొడవు(ptitle), 0, 0);
#లేదావేళ SPT_TYPE == SPT_REUSEARGV
/*	debug("setproctitle: copy \"%s\" into len %d",
	    buf, argv_env_len); */
	len = strlcpy(argv_ప్రారంభం, ptitle, argv_env_len);
	కొరకు(; len < argv_env_len; len++)
		argv_ప్రారంభం[len] = SPT_PADCHAR;
#అయితే_ముగింపు

#అయితే_ముగింపు /* SPT_NONE */
}

#అయితే_ముగింపు /* HAVE_SETPROCTITLE */
