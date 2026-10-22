/*	$OpenBSD: setenv.c,v 1.13 2010/08/23 22:31:50 millert Exp $ */
/*
 * Copyright (c) 1987 Regents of the University of California.
 * All rights reserved.
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

/* OPENBSD ORIGINAL: lib/libc/stdlib/setenv.c */

#അന്തര്ഭാവ "includes.h"

#എങ്കിൽ !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

ബാഹ്യ അക്ഷരം **environ;
#ifndef HAVE_SETENV
സ്ഥിതം അക്ഷരം **lastenv;				/* last value of environ */
#endif

/* OpenSSH Portable: __findenv is from getenv.c rev 1.8, made static */
/*
 * __findenv --
 *	Returns pointer to value associated with name, if any, else NULL.
 *	Starts searching within the environmental array at offset.
 *	Sets offset to be the offset of the name/value combination in the
 *	environmental array, for use by putenv(3), setenv(3) and unsetenv(3).
 *	Explicitly removes '=' in argument name.
 *
 *	This routine *should* be a static; don't use it.
 */
സ്ഥിതം അക്ഷരം *
__findenv(സ്ഥിരം അക്ഷരം *name, പൂർണ്ണസംഖ്യ len, പൂർണ്ണസംഖ്യ *offset)
{
	ബാഹ്യ അക്ഷരം **environ;
	പൂർണ്ണസംഖ്യ i;
	സ്ഥിരം അക്ഷരം *np;
	അക്ഷരം **p, *cp;

	എങ്കിൽ (name == ശൂന്യ || environ == ശൂന്യ)
		തിരികെ (ശൂന്യ);
	വേണ്ടി (p = environ + *offset; (cp = *p) != ശൂന്യ; ++p) {
		വേണ്ടി (np = name, i = len; i && *cp; i--)
			എങ്കിൽ (*cp++ != *np++)
				നിർത്തുക;
		എങ്കിൽ (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			തിരികെ (cp);
		}
	}
	തിരികെ (ശൂന്യ);
}

#എങ്കിൽ 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
പൂർണ്ണസംഖ്യ
putenv(അക്ഷരം *str)
{
	അക്ഷരം **P, *cp;
	size_t cnt;
	പൂർണ്ണസംഖ്യ offset = 0;

	വേണ്ടി (cp = str; *cp && *cp != '='; ++cp)
		;
	എങ്കിൽ (*cp != '=') {
		errno = EINVAL;
		തിരികെ (-1);			/* missing `=' in string */
	}

	എങ്കിൽ (__findenv(str, (പൂർണ്ണസംഖ്യ)(cp - str), &offset) != ശൂന്യ) {
		environ[offset++] = str;
		/* could be set multiple times */
		ആകുമ്പോൾ (__findenv(str, (പൂർണ്ണസംഖ്യ)(cp - str), &offset)) {
			വേണ്ടി (P = &environ[offset];; ++P)
				എങ്കിൽ (!(*P = *(P + 1)))
					നിർത്തുക;
		}
		തിരികെ (0);
	}

	/* create new slot for string */
	വേണ്ടി (P = environ; *P != ശൂന്യ; P++)
		;
	cnt = P - environ;
	P = (അക്ഷരം **)realloc(lastenv, വലുപ്പം(അക്ഷരം *) * (cnt + 2));
	എങ്കിൽ (!P)
		തിരികെ (-1);
	എങ്കിൽ (lastenv != environ)
		memcpy(P, environ, cnt * വലുപ്പം(അക്ഷരം *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = ശൂന്യ;
	തിരികെ (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
പൂർണ്ണസംഖ്യ
setenv(സ്ഥിരം അക്ഷരം *name, സ്ഥിരം അക്ഷരം *മൂല്യം, പൂർണ്ണസംഖ്യ rewrite)
{
	അക്ഷരം *C, **P;
	സ്ഥിരം അക്ഷരം *np;
	പൂർണ്ണസംഖ്യ l_മൂല്യം, offset = 0;

	വേണ്ടി (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	എങ്കിൽ (*np) {
		errno = EINVAL;
		തിരികെ (-1);			/* has `=' in name */
	}
#endif

	l_മൂല്യം = strlen(മൂല്യം);
	എങ്കിൽ ((C = __findenv(name, (പൂർണ്ണസംഖ്യ)(np - name), &offset)) != ശൂന്യ) {
		പൂർണ്ണസംഖ്യ tmpoff = offset + 1;
		എങ്കിൽ (!rewrite)
			തിരികെ (0);
#എങ്കിൽ 0 /* XXX - existing entry may not be writable */
		എങ്കിൽ (strlen(C) >= l_മൂല്യം) {	/* old larger; copy over */
			ആകുമ്പോൾ ((*C++ = *മൂല്യം++))
				;
			തിരികെ (0);
		}
#endif
		/* could be set multiple times */
		ആകുമ്പോൾ (__findenv(name, (പൂർണ്ണസംഖ്യ)(np - name), &tmpoff)) {
			വേണ്ടി (P = &environ[tmpoff];; ++P)
				എങ്കിൽ (!(*P = *(P + 1)))
					നിർത്തുക;
		}
	} അല്ലെങ്കിൽ {					/* create new slot */
		size_t cnt;

		വേണ്ടി (P = environ; *P != ശൂന്യ; P++)
			;
		cnt = P - environ;
		P = (അക്ഷരം **)realloc(lastenv, വലുപ്പം(അക്ഷരം *) * (cnt + 2));
		എങ്കിൽ (!P)
			തിരികെ (-1);
		എങ്കിൽ (lastenv != environ)
			memcpy(P, environ, cnt * വലുപ്പം(അക്ഷരം *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = ശൂന്യ;
	}
	എങ്കിൽ (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((പൂർണ്ണസംഖ്യ)(np - name) + l_മൂല്യം + 2))))
		തിരികെ (-1);
	വേണ്ടി (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	വേണ്ടി (*C++ = '='; (*C++ = *മൂല്യം++); )
		;
	തിരികെ (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
പൂർണ്ണസംഖ്യ
unsetenv(സ്ഥിരം അക്ഷരം *name)
{
	അക്ഷരം **P;
	സ്ഥിരം അക്ഷരം *np;
	പൂർണ്ണസംഖ്യ offset = 0;

	എങ്കിൽ (!name || !*name) {
		errno = EINVAL;
		തിരികെ (-1);
	}
	വേണ്ടി (np = name; *np && *np != '='; ++np)
		;
	എങ്കിൽ (*np) {
		errno = EINVAL;
		തിരികെ (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	ആകുമ്പോൾ (__findenv(name, (പൂർണ്ണസംഖ്യ)(np - name), &offset)) {
		വേണ്ടി (P = &environ[offset];; ++P)
			എങ്കിൽ (!(*P = *(P + 1)))
				നിർത്തുക;
	}
	തിരികെ (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

