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

#अन्तर्भाव "includes.h"

#जर !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

बाह्य अक्षर **environ;
#ifndef HAVE_SETENV
स्थिर अक्षर **lastenv;				/* last value of environ */
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
स्थिर अक्षर *
__findenv(स्थिरांक अक्षर *name, पूर्णांक len, पूर्णांक *offset)
{
	बाह्य अक्षर **environ;
	पूर्णांक i;
	स्थिरांक अक्षर *np;
	अक्षर **p, *cp;

	जर (name == रिक्त || environ == रिक्त)
		परत (रिक्त);
	साठी (p = environ + *offset; (cp = *p) != रिक्त; ++p) {
		साठी (np = name, i = len; i && *cp; i--)
			जर (*cp++ != *np++)
				थांबा;
		जर (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			परत (cp);
		}
	}
	परत (रिक्त);
}

#जर 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
पूर्णांक
putenv(अक्षर *str)
{
	अक्षर **P, *cp;
	माप_प्रकार cnt;
	पूर्णांक offset = 0;

	साठी (cp = str; *cp && *cp != '='; ++cp)
		;
	जर (*cp != '=') {
		त्रुटि_सं = EINVAL;
		परत (-1);			/* missing `=' in string */
	}

	जर (__findenv(str, (पूर्णांक)(cp - str), &offset) != रिक्त) {
		environ[offset++] = str;
		/* could be set multiple times */
		पर्यंत (__findenv(str, (पूर्णांक)(cp - str), &offset)) {
			साठी (P = &environ[offset];; ++P)
				जर (!(*P = *(P + 1)))
					थांबा;
		}
		परत (0);
	}

	/* create new slot for string */
	साठी (P = environ; *P != रिक्त; P++)
		;
	cnt = P - environ;
	P = (अक्षर **)पुनः_स्मृति(lastenv, आकार(अक्षर *) * (cnt + 2));
	जर (!P)
		परत (-1);
	जर (lastenv != environ)
		स_नकल(P, environ, cnt * आकार(अक्षर *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = रिक्त;
	परत (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
पूर्णांक
setenv(स्थिरांक अक्षर *name, स्थिरांक अक्षर *मूल्य, पूर्णांक rewrite)
{
	अक्षर *C, **P;
	स्थिरांक अक्षर *np;
	पूर्णांक l_मूल्य, offset = 0;

	साठी (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	जर (*np) {
		त्रुटि_सं = EINVAL;
		परत (-1);			/* has `=' in name */
	}
#endif

	l_मूल्य = म_माप(मूल्य);
	जर ((C = __findenv(name, (पूर्णांक)(np - name), &offset)) != रिक्त) {
		पूर्णांक tmpoff = offset + 1;
		जर (!rewrite)
			परत (0);
#जर 0 /* XXX - existing entry may not be writable */
		जर (म_माप(C) >= l_मूल्य) {	/* old larger; copy over */
			पर्यंत ((*C++ = *मूल्य++))
				;
			परत (0);
		}
#endif
		/* could be set multiple times */
		पर्यंत (__findenv(name, (पूर्णांक)(np - name), &tmpoff)) {
			साठी (P = &environ[tmpoff];; ++P)
				जर (!(*P = *(P + 1)))
					थांबा;
		}
	} अन्यथा {					/* create new slot */
		माप_प्रकार cnt;

		साठी (P = environ; *P != रिक्त; P++)
			;
		cnt = P - environ;
		P = (अक्षर **)पुनः_स्मृति(lastenv, आकार(अक्षर *) * (cnt + 2));
		जर (!P)
			परत (-1);
		जर (lastenv != environ)
			स_नकल(P, environ, cnt * आकार(अक्षर *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = रिक्त;
	}
	जर (!(environ[offset] =			/* name + `=' + value */
	    दो_स्मृति((माप_प्रकार)((पूर्णांक)(np - name) + l_मूल्य + 2))))
		परत (-1);
	साठी (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	साठी (*C++ = '='; (*C++ = *मूल्य++); )
		;
	परत (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
पूर्णांक
unsetenv(स्थिरांक अक्षर *name)
{
	अक्षर **P;
	स्थिरांक अक्षर *np;
	पूर्णांक offset = 0;

	जर (!name || !*name) {
		त्रुटि_सं = EINVAL;
		परत (-1);
	}
	साठी (np = name; *np && *np != '='; ++np)
		;
	जर (*np) {
		त्रुटि_सं = EINVAL;
		परत (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	पर्यंत (__findenv(name, (पूर्णांक)(np - name), &offset)) {
		साठी (P = &environ[offset];; ++P)
			जर (!(*P = *(P + 1)))
				थांबा;
	}
	परत (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

