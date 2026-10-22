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

#جيڪڏهن_وصف_نه_ٿيل HAVE_SETPROCTITLE

#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <unistd.h>
#جيڪڏهن_وصف_ٿيل HAVE_SYS_PSTAT_H
#ضمن <sys/pstat.h>
#جيڪڏهن_پورو
#ضمن <string.h>

#ضمن <vis.h>

#وصف_ڪريو SPT_NONE	0	/* don't use it at all */
#وصف_ڪريو SPT_PSTAT	1	/* use pstat(PSTAT_SETCMD, ...) */
#وصف_ڪريو SPT_REUSEARGV	2	/* cover argv with title information */

#جيڪڏهن_وصف_نه_ٿيل SPT_TYPE
# define SPT_TYPE	SPT_NONE
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل SPT_PADCHAR
# define SPT_PADCHAR	'\0'
#جيڪڏهن_پورو

#إذا SPT_TYPE == SPT_REUSEARGV
ساكن حرف *argv_شروعات = عدم;
ساكن سائيز_t argv_env_len = 0;
#جيڪڏهن_پورو

#جيڪڏهن_پورو /* HAVE_SETPROCTITLE */

فراغ
compat_init_setproctitle(صحيح argc, حرف *argv[])
{
#إذا !defined(HAVE_SETPROCTITLE) && \
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

	إذا (argc == 0 || argv[0] == عدم)
		أرجع;

	/* Fail if we can't allocate room for the new environment */
	لكل (i = 0; envp[i] != عدم; i++)
		;
	إذا ((environ = صفر_يادگيري_ڏيو(i + 1, حجم(*environ))) == عدم) {
		environ = envp;	/* put it back */
		أرجع;
	}

	/*
	 * Find the last argv string or environment variable within
	 * our process memory area.
	 */
	لكل (i = 0; i < argc; i++) {
		إذا (lastargv == عدم || lastargv + 1 == argv[i])
			lastargv = argv[i] + لڙي_ڊيگهه(argv[i]);
	}
	لكل (i = 0; envp[i] != عدم; i++) {
		إذا (lastargv + 1 == envp[i])
			lastargv = envp[i] + لڙي_ڊيگهه(envp[i]);
	}

	argv[1] = عدم;
	argv_شروعات = argv[0];
	argv_env_len = lastargv - argv[0] - 1;

	/*
	 * Copy environment
	 * XXX - will truncate env on strdup fail
	 */
	لكل (i = 0; envp[i] != عدم; i++)
		environ[i] = strdup(envp[i]);
	environ[i] = عدم;
#جيڪڏهن_پورو /* SPT_REUSEARGV */
}

#جيڪڏهن_وصف_نه_ٿيل HAVE_SETPROCTITLE
فراغ
setproctitle(ثابت حرف *fmt, ...)
{
#إذا SPT_TYPE != SPT_NONE
	va_list ap;
	حرف buf[1024], ptitle[1024];
	سائيز_t len = 0;
	صحيح r;
	خارجي حرف *__progname;
#إذا SPT_TYPE == SPT_PSTAT
	اتحاد pstun pst;
#جيڪڏهن_پورو

#إذا SPT_TYPE == SPT_REUSEARGV
	إذا (argv_env_len <= 0)
		أرجع;
#جيڪڏهن_پورو

	strlcpy(buf, __progname, حجم(buf));

	r = -1;
	va_start(ap, fmt);
	إذا (fmt != عدم) {
		len = strlcat(buf, ": ", حجم(buf));
		إذا (len < حجم(buf))
			r = vsnprintf(buf + len, حجم(buf) - len , fmt, ap);
	}
	va_end(ap);
	إذا (r == -1 || (سائيز_t)r >= حجم(buf) - len)
		أرجع;
	strnvis(ptitle, buf, حجم(ptitle),
	    VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL);

#إذا SPT_TYPE == SPT_PSTAT
	pst.pst_command = ptitle;
	pstat(PSTAT_SETCMD, pst, لڙي_ڊيگهه(ptitle), 0, 0);
#وإلاإذا SPT_TYPE == SPT_REUSEARGV
/*	debug("setproctitle: copy \"%s\" into len %d",
	    buf, argv_env_len); */
	len = strlcpy(argv_شروعات, ptitle, argv_env_len);
	لكل(; len < argv_env_len; len++)
		argv_شروعات[len] = SPT_PADCHAR;
#جيڪڏهن_پورو

#جيڪڏهن_پورو /* SPT_NONE */
}

#جيڪڏهن_پورو /* HAVE_SETPROCTITLE */
