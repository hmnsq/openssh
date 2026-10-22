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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SETPROCTITLE

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_PSTAT_H
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/pstat.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <vis.h>

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPT_NONE	0	/* don't use it at all */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPT_PSTAT	1	/* use pstat(PSTAT_SETCMD, ...) */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPT_REUSEARGV	2	/* cover argv with title information */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SPT_TYPE
# define SPT_TYPE	SPT_NONE
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SPT_PADCHAR
# define SPT_PADCHAR	'\0'
#ਜੇ_ਅੰਤ

#ਜੇ SPT_TYPE == SPT_REUSEARGV
ਸਥਿਰ ਅੱਖਰ *argv_ਸ਼ੁਰੂ = ਨਿਰਾ;
ਸਥਿਰ ਮਾਪ_t argv_env_len = 0;
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ /* HAVE_SETPROCTITLE */

ਖਾਲੀ
compat_init_setproctitle(ਪੂਰਨ argc, ਅੱਖਰ *argv[])
{
#ਜੇ !defined(HAVE_SETPROCTITLE) && \
    defined(SPT_TYPE) && SPT_TYPE == SPT_REUSEARGV
	ਬਾਹਰੀ ਅੱਖਰ **environ;
	ਅੱਖਰ *lastargv = ਨਿਰਾ;
	ਅੱਖਰ **envp = environ;
	ਪੂਰਨ i;

	/*
	 * NB: This assumes that argv has already been copied out of the
	 * way. This is true for sshd, but may not be true for other
	 * programs. Beware.
	 */

	ਜੇ (argc == 0 || argv[0] == ਨਿਰਾ)
		ਵਾਪਸ;

	/* Fail if we can't allocate room for the new environment */
	ਲਈ (i = 0; envp[i] != ਨਿਰਾ; i++)
		;
	ਜੇ ((environ = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(i + 1, ਆਕਾਰ(*environ))) == ਨਿਰਾ) {
		environ = envp;	/* put it back */
		ਵਾਪਸ;
	}

	/*
	 * Find the last argv string or environment variable within
	 * our process memory area.
	 */
	ਲਈ (i = 0; i < argc; i++) {
		ਜੇ (lastargv == ਨਿਰਾ || lastargv + 1 == argv[i])
			lastargv = argv[i] + ਲੜੀ_ਲੰਬਾਈ(argv[i]);
	}
	ਲਈ (i = 0; envp[i] != ਨਿਰਾ; i++) {
		ਜੇ (lastargv + 1 == envp[i])
			lastargv = envp[i] + ਲੜੀ_ਲੰਬਾਈ(envp[i]);
	}

	argv[1] = ਨਿਰਾ;
	argv_ਸ਼ੁਰੂ = argv[0];
	argv_env_len = lastargv - argv[0] - 1;

	/*
	 * Copy environment
	 * XXX - will truncate env on strdup fail
	 */
	ਲਈ (i = 0; envp[i] != ਨਿਰਾ; i++)
		environ[i] = strdup(envp[i]);
	environ[i] = ਨਿਰਾ;
#ਜੇ_ਅੰਤ /* SPT_REUSEARGV */
}

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SETPROCTITLE
ਖਾਲੀ
setproctitle(ਅਚਲ ਅੱਖਰ *fmt, ...)
{
#ਜੇ SPT_TYPE != SPT_NONE
	va_list ap;
	ਅੱਖਰ buf[1024], ptitle[1024];
	ਮਾਪ_t len = 0;
	ਪੂਰਨ r;
	ਬਾਹਰੀ ਅੱਖਰ *__progname;
#ਜੇ SPT_TYPE == SPT_PSTAT
	ਸੰਘ pstun pst;
#ਜੇ_ਅੰਤ

#ਜੇ SPT_TYPE == SPT_REUSEARGV
	ਜੇ (argv_env_len <= 0)
		ਵਾਪਸ;
#ਜੇ_ਅੰਤ

	strlcpy(buf, __progname, ਆਕਾਰ(buf));

	r = -1;
	va_start(ap, fmt);
	ਜੇ (fmt != ਨਿਰਾ) {
		len = strlcat(buf, ": ", ਆਕਾਰ(buf));
		ਜੇ (len < ਆਕਾਰ(buf))
			r = vsnprintf(buf + len, ਆਕਾਰ(buf) - len , fmt, ap);
	}
	va_end(ap);
	ਜੇ (r == -1 || (ਮਾਪ_t)r >= ਆਕਾਰ(buf) - len)
		ਵਾਪਸ;
	strnvis(ptitle, buf, ਆਕਾਰ(ptitle),
	    VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL);

#ਜੇ SPT_TYPE == SPT_PSTAT
	pst.pst_command = ptitle;
	pstat(PSTAT_SETCMD, pst, ਲੜੀ_ਲੰਬਾਈ(ptitle), 0, 0);
#ਜਾਂਜੇ SPT_TYPE == SPT_REUSEARGV
/*	debug("setproctitle: copy \"%s\" into len %d",
	    buf, argv_env_len); */
	len = strlcpy(argv_ਸ਼ੁਰੂ, ptitle, argv_env_len);
	ਲਈ(; len < argv_env_len; len++)
		argv_ਸ਼ੁਰੂ[len] = SPT_PADCHAR;
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ /* SPT_NONE */
}

#ਜੇ_ਅੰਤ /* HAVE_SETPROCTITLE */
