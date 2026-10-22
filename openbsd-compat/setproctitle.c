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

#अन्तर्भाव "includes.h"

#यदि_अपरिभाषितम् HAVE_SETPROCTITLE

#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <unistd.h>
#यदि_परिभाषितम् HAVE_SYS_PSTAT_H
#अन्तर्भाव <sys/pstat.h>
#यदि_अन्तः
#अन्तर्भाव <string.h>

#अन्तर्भाव <vis.h>

#परिभाषय SPT_NONE	0	/* don't use it at all */
#परिभाषय SPT_PSTAT	1	/* use pstat(PSTAT_SETCMD, ...) */
#परिभाषय SPT_REUSEARGV	2	/* cover argv with title information */

#यदि_अपरिभाषितम् SPT_TYPE
# define SPT_TYPE	SPT_NONE
#यदि_अन्तः

#यदि_अपरिभाषितम् SPT_PADCHAR
# define SPT_PADCHAR	'\0'
#यदि_अन्तः

#यदि SPT_TYPE == SPT_REUSEARGV
स्थिर वर्ण *argv_start = रिक्त;
स्थिर आकार_t argv_env_len = 0;
#यदि_अन्तः

#यदि_अन्तः /* HAVE_SETPROCTITLE */

शून्य
compat_init_setproctitle(पूर्णाङ्क argc, वर्ण *argv[])
{
#यदि !defined(HAVE_SETPROCTITLE) && \
    defined(SPT_TYPE) && SPT_TYPE == SPT_REUSEARGV
	बाह्य वर्ण **environ;
	वर्ण *lastargv = रिक्त;
	वर्ण **envp = environ;
	पूर्णाङ्क i;

	/*
	 * NB: This assumes that argv has already been copied out of the
	 * way. This is true for sshd, but may not be true for other
	 * programs. Beware.
	 */

	यदि (argc == 0 || argv[0] == रिक्त)
		प्रत्यागम;

	/* Fail if we can't allocate room for the new environment */
	प्रति (i = 0; envp[i] != रिक्त; i++)
		;
	यदि ((environ = शून्यस्मृतिं_देहि(i + 1, परिमाण(*environ))) == रिक्त) {
		environ = envp;	/* put it back */
		प्रत्यागम;
	}

	/*
	 * Find the last argv string or environment variable within
	 * our process memory area.
	 */
	प्रति (i = 0; i < argc; i++) {
		यदि (lastargv == रिक्त || lastargv + 1 == argv[i])
			lastargv = argv[i] + वाक्यदैर्घ्यम्(argv[i]);
	}
	प्रति (i = 0; envp[i] != रिक्त; i++) {
		यदि (lastargv + 1 == envp[i])
			lastargv = envp[i] + वाक्यदैर्घ्यम्(envp[i]);
	}

	argv[1] = रिक्त;
	argv_start = argv[0];
	argv_env_len = lastargv - argv[0] - 1;

	/*
	 * Copy environment
	 * XXX - will truncate env on strdup fail
	 */
	प्रति (i = 0; envp[i] != रिक्त; i++)
		environ[i] = strdup(envp[i]);
	environ[i] = रिक्त;
#यदि_अन्तः /* SPT_REUSEARGV */
}

#यदि_अपरिभाषितम् HAVE_SETPROCTITLE
शून्य
setproctitle(ध्रुव वर्ण *fmt, ...)
{
#यदि SPT_TYPE != SPT_NONE
	va_list ap;
	वर्ण buf[1024], ptitle[1024];
	आकार_t len = 0;
	पूर्णाङ्क r;
	बाह्य वर्ण *__progname;
#यदि SPT_TYPE == SPT_PSTAT
	सङ्घ pstun pst;
#यदि_अन्तः

#यदि SPT_TYPE == SPT_REUSEARGV
	यदि (argv_env_len <= 0)
		प्रत्यागम;
#यदि_अन्तः

	strlcpy(buf, __progname, परिमाण(buf));

	r = -1;
	va_start(ap, fmt);
	यदि (fmt != रिक्त) {
		len = strlcat(buf, ": ", परिमाण(buf));
		यदि (len < परिमाण(buf))
			r = vsnprintf(buf + len, परिमाण(buf) - len , fmt, ap);
	}
	va_end(ap);
	यदि (r == -1 || (आकार_t)r >= परिमाण(buf) - len)
		प्रत्यागम;
	strnvis(ptitle, buf, परिमाण(ptitle),
	    VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL);

#यदि SPT_TYPE == SPT_PSTAT
	pst.pst_command = ptitle;
	pstat(PSTAT_SETCMD, pst, वाक्यदैर्घ्यम्(ptitle), 0, 0);
#नोचेद्यदि SPT_TYPE == SPT_REUSEARGV
/*	debug("setproctitle: copy \"%s\" into len %d",
	    buf, argv_env_len); */
	len = strlcpy(argv_start, ptitle, argv_env_len);
	प्रति(; len < argv_env_len; len++)
		argv_start[len] = SPT_PADCHAR;
#यदि_अन्तः

#यदि_अन्तः /* SPT_NONE */
}

#यदि_अन्तः /* HAVE_SETPROCTITLE */
