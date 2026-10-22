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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SETPROCTITLE

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_PSTAT_H
#ಅನ್ತರ್ಭಾವ <sys/pstat.h>
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ <vis.h>

#ವ್ಯಾಖ್ಯಾನಿಸು SPT_NONE	0	/* don't use it at all */
#ವ್ಯಾಖ್ಯಾನಿಸು SPT_PSTAT	1	/* use pstat(PSTAT_SETCMD, ...) */
#ವ್ಯಾಖ್ಯಾನಿಸು SPT_REUSEARGV	2	/* cover argv with title information */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SPT_TYPE
# define SPT_TYPE	SPT_NONE
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SPT_PADCHAR
# define SPT_PADCHAR	'\0'
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ SPT_TYPE == SPT_REUSEARGV
ಸ್ಥಿರ ಅಕ್ಷರ *argv_ಆರಂಭ = ಖಾಲಿ;
ಸ್ಥಿರ ಗಾತ್ರ_t argv_env_len = 0;
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_SETPROCTITLE */

ಶೂನ್ಯ
compat_init_setproctitle(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ *argv[])
{
#ಆದರೆ !defined(HAVE_SETPROCTITLE) && \
    defined(SPT_TYPE) && SPT_TYPE == SPT_REUSEARGV
	ಬಾಹ್ಯ ಅಕ್ಷರ **environ;
	ಅಕ್ಷರ *lastargv = ಖಾಲಿ;
	ಅಕ್ಷರ **envp = environ;
	ಪೂರ್ಣಾಂಕ i;

	/*
	 * NB: This assumes that argv has already been copied out of the
	 * way. This is true for sshd, but may not be true for other
	 * programs. Beware.
	 */

	ಆದರೆ (argc == 0 || argv[0] == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	/* Fail if we can't allocate room for the new environment */
	ಗಾಗಿ (i = 0; envp[i] != ಖಾಲಿ; i++)
		;
	ಆದರೆ ((environ = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(i + 1, ಗಾತ್ರ(*environ))) == ಖಾಲಿ) {
		environ = envp;	/* put it back */
		ಹಿಂತಿರುಗಿ;
	}

	/*
	 * Find the last argv string or environment variable within
	 * our process memory area.
	 */
	ಗಾಗಿ (i = 0; i < argc; i++) {
		ಆದರೆ (lastargv == ಖಾಲಿ || lastargv + 1 == argv[i])
			lastargv = argv[i] + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(argv[i]);
	}
	ಗಾಗಿ (i = 0; envp[i] != ಖಾಲಿ; i++) {
		ಆದರೆ (lastargv + 1 == envp[i])
			lastargv = envp[i] + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(envp[i]);
	}

	argv[1] = ಖಾಲಿ;
	argv_ಆರಂಭ = argv[0];
	argv_env_len = lastargv - argv[0] - 1;

	/*
	 * Copy environment
	 * XXX - will truncate env on strdup fail
	 */
	ಗಾಗಿ (i = 0; envp[i] != ಖಾಲಿ; i++)
		environ[i] = strdup(envp[i]);
	environ[i] = ಖಾಲಿ;
#ಆದರೆ_ಅಂತ್ಯ /* SPT_REUSEARGV */
}

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SETPROCTITLE
ಶೂನ್ಯ
setproctitle(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
#ಆದರೆ SPT_TYPE != SPT_NONE
	va_list ap;
	ಅಕ್ಷರ buf[1024], ptitle[1024];
	ಗಾತ್ರ_t len = 0;
	ಪೂರ್ಣಾಂಕ r;
	ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;
#ಆದರೆ SPT_TYPE == SPT_PSTAT
	ಒಕ್ಕೂಟ pstun pst;
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ SPT_TYPE == SPT_REUSEARGV
	ಆದರೆ (argv_env_len <= 0)
		ಹಿಂತಿರುಗಿ;
#ಆದರೆ_ಅಂತ್ಯ

	strlcpy(buf, __progname, ಗಾತ್ರ(buf));

	r = -1;
	va_start(ap, fmt);
	ಆದರೆ (fmt != ಖಾಲಿ) {
		len = strlcat(buf, ": ", ಗಾತ್ರ(buf));
		ಆದರೆ (len < ಗಾತ್ರ(buf))
			r = vsnprintf(buf + len, ಗಾತ್ರ(buf) - len , fmt, ap);
	}
	va_end(ap);
	ಆದರೆ (r == -1 || (ಗಾತ್ರ_t)r >= ಗಾತ್ರ(buf) - len)
		ಹಿಂತಿರುಗಿ;
	strnvis(ptitle, buf, ಗಾತ್ರ(ptitle),
	    VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL);

#ಆದರೆ SPT_TYPE == SPT_PSTAT
	pst.pst_command = ptitle;
	pstat(PSTAT_SETCMD, pst, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ptitle), 0, 0);
#ಅಥವಾಆದರೆ SPT_TYPE == SPT_REUSEARGV
/*	debug("setproctitle: copy \"%s\" into len %d",
	    buf, argv_env_len); */
	len = strlcpy(argv_ಆರಂಭ, ptitle, argv_env_len);
	ಗಾಗಿ(; len < argv_env_len; len++)
		argv_ಆರಂಭ[len] = SPT_PADCHAR;
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ /* SPT_NONE */
}

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_SETPROCTITLE */
