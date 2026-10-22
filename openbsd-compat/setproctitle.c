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

#समावेश "includes.h"

#अगर_अघोषित HAVE_SETPROCTITLE

#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <unistd.h>
#अगर_घोषित HAVE_SYS_PSTAT_H
#समावेश <sys/pstat.h>
#पूर्ण_अगर
#समावेश <string.h>

#समावेश <vis.h>

#घोषणा SPT_NONE	0	/* don't use it at all */
#घोषणा SPT_PSTAT	1	/* use pstat(PSTAT_SETCMD, ...) */
#घोषणा SPT_REUSEARGV	2	/* cover argv with title information */

#अगर_अघोषित SPT_TYPE
# define SPT_TYPE	SPT_NONE
#पूर्ण_अगर

#अगर_अघोषित SPT_PADCHAR
# define SPT_PADCHAR	'\0'
#पूर्ण_अगर

#अगर SPT_TYPE == SPT_REUSEARGV
अटल अक्षर *argv_start = शून्य;
अटल माप_प्रकार argv_env_len = 0;
#पूर्ण_अगर

#पूर्ण_अगर /* HAVE_SETPROCTITLE */

व्योम
compat_init_setproctitle(पूर्णांक argc, अक्षर *argv[])
{
#अगर !defined(HAVE_SETPROCTITLE) && \
    defined(SPT_TYPE) && SPT_TYPE == SPT_REUSEARGV
	बाह्य अक्षर **environ;
	अक्षर *lastargv = शून्य;
	अक्षर **envp = environ;
	पूर्णांक i;

	/*
	 * NB: This assumes that argv has already been copied out of the
	 * way. This is true for sshd, but may not be true for other
	 * programs. Beware.
	 */

	अगर (argc == 0 || argv[0] == शून्य)
		वापस;

	/* Fail if we can't allocate room for the new environment */
	क्रम (i = 0; envp[i] != शून्य; i++)
		;
	अगर ((environ = सुस्मृति(i + 1, माप(*environ))) == शून्य) {
		environ = envp;	/* put it back */
		वापस;
	}

	/*
	 * Find the last argv string or environment variable within
	 * our process memory area.
	 */
	क्रम (i = 0; i < argc; i++) {
		अगर (lastargv == शून्य || lastargv + 1 == argv[i])
			lastargv = argv[i] + म_माप(argv[i]);
	}
	क्रम (i = 0; envp[i] != शून्य; i++) {
		अगर (lastargv + 1 == envp[i])
			lastargv = envp[i] + म_माप(envp[i]);
	}

	argv[1] = शून्य;
	argv_start = argv[0];
	argv_env_len = lastargv - argv[0] - 1;

	/*
	 * Copy environment
	 * XXX - will truncate env on strdup fail
	 */
	क्रम (i = 0; envp[i] != शून्य; i++)
		environ[i] = strdup(envp[i]);
	environ[i] = शून्य;
#पूर्ण_अगर /* SPT_REUSEARGV */
}

#अगर_अघोषित HAVE_SETPROCTITLE
व्योम
setproctitle(स्थिर अक्षर *fmt, ...)
{
#अगर SPT_TYPE != SPT_NONE
	बहु_सूची ap;
	अक्षर buf[1024], ptitle[1024];
	माप_प्रकार len = 0;
	पूर्णांक r;
	बाह्य अक्षर *__progname;
#अगर SPT_TYPE == SPT_PSTAT
	जोड़ pstun pst;
#पूर्ण_अगर

#अगर SPT_TYPE == SPT_REUSEARGV
	अगर (argv_env_len <= 0)
		वापस;
#पूर्ण_अगर

	strlcpy(buf, __progname, माप(buf));

	r = -1;
	बहु_शुरू(ap, fmt);
	अगर (fmt != शून्य) {
		len = strlcat(buf, ": ", माप(buf));
		अगर (len < माप(buf))
			r = vsnprintf(buf + len, माप(buf) - len , fmt, ap);
	}
	बहु_पूर्ण(ap);
	अगर (r == -1 || (माप_प्रकार)r >= माप(buf) - len)
		वापस;
	strnvis(ptitle, buf, माप(ptitle),
	    VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL);

#अगर SPT_TYPE == SPT_PSTAT
	pst.pst_command = ptitle;
	pstat(PSTAT_SETCMD, pst, म_माप(ptitle), 0, 0);
#या_अगर SPT_TYPE == SPT_REUSEARGV
/*	debug("setproctitle: copy \"%s\" into len %d",
	    buf, argv_env_len); */
	len = strlcpy(argv_start, ptitle, argv_env_len);
	क्रम(; len < argv_env_len; len++)
		argv_start[len] = SPT_PADCHAR;
#पूर्ण_अगर

#पूर्ण_अगर /* SPT_NONE */
}

#पूर्ण_अगर /* HAVE_SETPROCTITLE */
