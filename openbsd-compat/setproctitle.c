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

#অন্তর্ভাব "includes.h"

#ifndef HAVE_SETPROCTITLE

#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <unistd.h>
#ifdef HAVE_SYS_PSTAT_H
#অন্তর্ভাব <sys/pstat.h>
#endif
#অন্তর্ভাব <string.h>

#অন্তর্ভাব <vis.h>

#define SPT_NONE	0	/* don't use it at all */
#define SPT_PSTAT	1	/* use pstat(PSTAT_SETCMD, ...) */
#define SPT_REUSEARGV	2	/* cover argv with title information */

#ifndef SPT_TYPE
# define SPT_TYPE	SPT_NONE
#endif

#ifndef SPT_PADCHAR
# define SPT_PADCHAR	'\0'
#endif

#যদি SPT_TYPE == SPT_REUSEARGV
স্থির বর্ণ *argv_start = রিক্ত;
স্থির size_t argv_env_len = 0;
#endif

#endif /* HAVE_SETPROCTITLE */

শূন্য
compat_init_setproctitle(পূর্ণাঙ্ক argc, বর্ণ *argv[])
{
#যদি !defined(HAVE_SETPROCTITLE) && \
    defined(SPT_TYPE) && SPT_TYPE == SPT_REUSEARGV
	বাহ্য বর্ণ **environ;
	বর্ণ *lastargv = রিক্ত;
	বর্ণ **envp = environ;
	পূর্ণাঙ্ক i;

	/*
	 * NB: This assumes that argv has already been copied out of the
	 * way. This is true for sshd, but may not be true for other
	 * programs. Beware.
	 */

	যদি (argc == 0 || argv[0] == রিক্ত)
		প্রত্যাগম;

	/* Fail if we can't allocate room for the new environment */
	প্রতি (i = 0; envp[i] != রিক্ত; i++)
		;
	যদি ((environ = calloc(i + 1, পরিমাণ(*environ))) == রিক্ত) {
		environ = envp;	/* put it back */
		প্রত্যাগম;
	}

	/*
	 * Find the last argv string or environment variable within
	 * our process memory area.
	 */
	প্রতি (i = 0; i < argc; i++) {
		যদি (lastargv == রিক্ত || lastargv + 1 == argv[i])
			lastargv = argv[i] + strlen(argv[i]);
	}
	প্রতি (i = 0; envp[i] != রিক্ত; i++) {
		যদি (lastargv + 1 == envp[i])
			lastargv = envp[i] + strlen(envp[i]);
	}

	argv[1] = রিক্ত;
	argv_start = argv[0];
	argv_env_len = lastargv - argv[0] - 1;

	/*
	 * Copy environment
	 * XXX - will truncate env on strdup fail
	 */
	প্রতি (i = 0; envp[i] != রিক্ত; i++)
		environ[i] = strdup(envp[i]);
	environ[i] = রিক্ত;
#endif /* SPT_REUSEARGV */
}

#ifndef HAVE_SETPROCTITLE
শূন্য
setproctitle(ধ্রুব বর্ণ *fmt, ...)
{
#যদি SPT_TYPE != SPT_NONE
	va_list ap;
	বর্ণ buf[1024], ptitle[1024];
	size_t len = 0;
	পূর্ণাঙ্ক r;
	বাহ্য বর্ণ *__progname;
#যদি SPT_TYPE == SPT_PSTAT
	সঙ্ঘ pstun pst;
#endif

#যদি SPT_TYPE == SPT_REUSEARGV
	যদি (argv_env_len <= 0)
		প্রত্যাগম;
#endif

	strlcpy(buf, __progname, পরিমাণ(buf));

	r = -1;
	va_start(ap, fmt);
	যদি (fmt != রিক্ত) {
		len = strlcat(buf, ": ", পরিমাণ(buf));
		যদি (len < পরিমাণ(buf))
			r = vsnprintf(buf + len, পরিমাণ(buf) - len , fmt, ap);
	}
	va_end(ap);
	যদি (r == -1 || (size_t)r >= পরিমাণ(buf) - len)
		প্রত্যাগম;
	strnvis(ptitle, buf, পরিমাণ(ptitle),
	    VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL);

#যদি SPT_TYPE == SPT_PSTAT
	pst.pst_command = ptitle;
	pstat(PSTAT_SETCMD, pst, strlen(ptitle), 0, 0);
#নোচেদ্যদি SPT_TYPE == SPT_REUSEARGV
/*	debug("setproctitle: copy \"%s\" into len %d",
	    buf, argv_env_len); */
	len = strlcpy(argv_start, ptitle, argv_env_len);
	প্রতি(; len < argv_env_len; len++)
		argv_start[len] = SPT_PADCHAR;
#endif

#endif /* SPT_NONE */
}

#endif /* HAVE_SETPROCTITLE */
