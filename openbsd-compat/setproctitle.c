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

#شامل "includes.h"

#اگر_غیر_تعریف_شدہ HAVE_SETPROCTITLE

#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <unistd.h>
#اگر_تعریف_شدہ HAVE_SYS_PSTAT_H
#شامل <sys/pstat.h>
#اگر_ختم
#شامل <string.h>

#شامل <vis.h>

#تعریف_کرو SPT_NONE	0	/* don't use it at all */
#تعریف_کرو SPT_PSTAT	1	/* use pstat(PSTAT_SETCMD, ...) */
#تعریف_کرو SPT_REUSEARGV	2	/* cover argv with title information */

#اگر_غیر_تعریف_شدہ SPT_TYPE
# define SPT_TYPE	SPT_NONE
#اگر_ختم

#اگر_غیر_تعریف_شدہ SPT_PADCHAR
# define SPT_PADCHAR	'\0'
#اگر_ختم

#اگر SPT_TYPE == SPT_REUSEARGV
ساکن حرف *argv_آغاز = تہی;
ساکن سائز_t argv_env_len = 0;
#اگر_ختم

#اگر_ختم /* HAVE_SETPROCTITLE */

خالی
compat_init_setproctitle(صحیح argc, حرف *argv[])
{
#اگر !defined(HAVE_SETPROCTITLE) && \
    defined(SPT_TYPE) && SPT_TYPE == SPT_REUSEARGV
	خارجی حرف **environ;
	حرف *lastargv = تہی;
	حرف **envp = environ;
	صحیح i;

	/*
	 * NB: This assumes that argv has already been copied out of the
	 * way. This is true for sshd, but may not be true for other
	 * programs. Beware.
	 */

	اگر (argc == 0 || argv[0] == تہی)
		واپس;

	/* Fail if we can't allocate room for the new environment */
	برائے (i = 0; envp[i] != تہی; i++)
		;
	اگر ((environ = صفر_حافظہ_دو(i + 1, حجم(*environ))) == تہی) {
		environ = envp;	/* put it back */
		واپس;
	}

	/*
	 * Find the last argv string or environment variable within
	 * our process memory area.
	 */
	برائے (i = 0; i < argc; i++) {
		اگر (lastargv == تہی || lastargv + 1 == argv[i])
			lastargv = argv[i] + لڑی_لمبائی(argv[i]);
	}
	برائے (i = 0; envp[i] != تہی; i++) {
		اگر (lastargv + 1 == envp[i])
			lastargv = envp[i] + لڑی_لمبائی(envp[i]);
	}

	argv[1] = تہی;
	argv_آغاز = argv[0];
	argv_env_len = lastargv - argv[0] - 1;

	/*
	 * Copy environment
	 * XXX - will truncate env on strdup fail
	 */
	برائے (i = 0; envp[i] != تہی; i++)
		environ[i] = strdup(envp[i]);
	environ[i] = تہی;
#اگر_ختم /* SPT_REUSEARGV */
}

#اگر_غیر_تعریف_شدہ HAVE_SETPROCTITLE
خالی
setproctitle(ثابت حرف *fmt, ...)
{
#اگر SPT_TYPE != SPT_NONE
	va_list ap;
	حرف buf[1024], ptitle[1024];
	سائز_t len = 0;
	صحیح r;
	خارجی حرف *__progname;
#اگر SPT_TYPE == SPT_PSTAT
	اتحاد pstun pst;
#اگر_ختم

#اگر SPT_TYPE == SPT_REUSEARGV
	اگر (argv_env_len <= 0)
		واپس;
#اگر_ختم

	strlcpy(buf, __progname, حجم(buf));

	r = -1;
	va_start(ap, fmt);
	اگر (fmt != تہی) {
		len = strlcat(buf, ": ", حجم(buf));
		اگر (len < حجم(buf))
			r = vsnprintf(buf + len, حجم(buf) - len , fmt, ap);
	}
	va_end(ap);
	اگر (r == -1 || (سائز_t)r >= حجم(buf) - len)
		واپس;
	strnvis(ptitle, buf, حجم(ptitle),
	    VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL);

#اگر SPT_TYPE == SPT_PSTAT
	pst.pst_command = ptitle;
	pstat(PSTAT_SETCMD, pst, لڑی_لمبائی(ptitle), 0, 0);
#وگرنہ_اگر SPT_TYPE == SPT_REUSEARGV
/*	debug("setproctitle: copy \"%s\" into len %d",
	    buf, argv_env_len); */
	len = strlcpy(argv_آغاز, ptitle, argv_env_len);
	برائے(; len < argv_env_len; len++)
		argv_آغاز[len] = SPT_PADCHAR;
#اگر_ختم

#اگر_ختم /* SPT_NONE */
}

#اگر_ختم /* HAVE_SETPROCTITLE */
