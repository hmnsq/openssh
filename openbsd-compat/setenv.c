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

#समावेश "includes.h"

#अगर !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#समावेश <errno.h>
#समावेश <stdlib.h>
#समावेश <string.h>

बाह्य अक्षर **environ;
#अगर_अघोषित HAVE_SETENV
अटल अक्षर **lastenv;				/* last value of environ */
#पूर्ण_अगर

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
अटल अक्षर *
__findenv(स्थिर अक्षर *name, पूर्णांक len, पूर्णांक *offset)
{
	बाह्य अक्षर **environ;
	पूर्णांक i;
	स्थिर अक्षर *np;
	अक्षर **p, *cp;

	अगर (name == शून्य || environ == शून्य)
		वापस (शून्य);
	क्रम (p = environ + *offset; (cp = *p) != शून्य; ++p) {
		क्रम (np = name, i = len; i && *cp; i--)
			अगर (*cp++ != *np++)
				अवरोध;
		अगर (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			वापस (cp);
		}
	}
	वापस (शून्य);
}

#अगर 0 /* nothing uses putenv */
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

	क्रम (cp = str; *cp && *cp != '='; ++cp)
		;
	अगर (*cp != '=') {
		त्रुटि_सं = EINVAL;
		वापस (-1);			/* missing `=' in string */
	}

	अगर (__findenv(str, (पूर्णांक)(cp - str), &offset) != शून्य) {
		environ[offset++] = str;
		/* could be set multiple times */
		जबतक (__findenv(str, (पूर्णांक)(cp - str), &offset)) {
			क्रम (P = &environ[offset];; ++P)
				अगर (!(*P = *(P + 1)))
					अवरोध;
		}
		वापस (0);
	}

	/* create new slot for string */
	क्रम (P = environ; *P != शून्य; P++)
		;
	cnt = P - environ;
	P = (अक्षर **)पुनः_स्मृति(lastenv, माप(अक्षर *) * (cnt + 2));
	अगर (!P)
		वापस (-1);
	अगर (lastenv != environ)
		स_नकल(P, environ, cnt * माप(अक्षर *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = शून्य;
	वापस (0);
}

#पूर्ण_अगर

#अगर_अघोषित HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
पूर्णांक
setenv(स्थिर अक्षर *name, स्थिर अक्षर *मूल्य, पूर्णांक rewrite)
{
	अक्षर *C, **P;
	स्थिर अक्षर *np;
	पूर्णांक l_मूल्य, offset = 0;

	क्रम (np = name; *np && *np != '='; ++np)
		;
#अगर_घोषित notyet
	अगर (*np) {
		त्रुटि_सं = EINVAL;
		वापस (-1);			/* has `=' in name */
	}
#पूर्ण_अगर

	l_मूल्य = म_माप(मूल्य);
	अगर ((C = __findenv(name, (पूर्णांक)(np - name), &offset)) != शून्य) {
		पूर्णांक tmpoff = offset + 1;
		अगर (!rewrite)
			वापस (0);
#अगर 0 /* XXX - existing entry may not be writable */
		अगर (म_माप(C) >= l_मूल्य) {	/* old larger; copy over */
			जबतक ((*C++ = *मूल्य++))
				;
			वापस (0);
		}
#पूर्ण_अगर
		/* could be set multiple times */
		जबतक (__findenv(name, (पूर्णांक)(np - name), &tmpoff)) {
			क्रम (P = &environ[tmpoff];; ++P)
				अगर (!(*P = *(P + 1)))
					अवरोध;
		}
	} अन्यथा {					/* create new slot */
		माप_प्रकार cnt;

		क्रम (P = environ; *P != शून्य; P++)
			;
		cnt = P - environ;
		P = (अक्षर **)पुनः_स्मृति(lastenv, माप(अक्षर *) * (cnt + 2));
		अगर (!P)
			वापस (-1);
		अगर (lastenv != environ)
			स_नकल(P, environ, cnt * माप(अक्षर *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = शून्य;
	}
	अगर (!(environ[offset] =			/* name + `=' + value */
	    दो_स्मृति((माप_प्रकार)((पूर्णांक)(np - name) + l_मूल्य + 2))))
		वापस (-1);
	क्रम (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	क्रम (*C++ = '='; (*C++ = *मूल्य++); )
		;
	वापस (0);
}

#पूर्ण_अगर /* HAVE_SETENV */

#अगर_अघोषित HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
पूर्णांक
unsetenv(स्थिर अक्षर *name)
{
	अक्षर **P;
	स्थिर अक्षर *np;
	पूर्णांक offset = 0;

	अगर (!name || !*name) {
		त्रुटि_सं = EINVAL;
		वापस (-1);
	}
	क्रम (np = name; *np && *np != '='; ++np)
		;
	अगर (*np) {
		त्रुटि_सं = EINVAL;
		वापस (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	जबतक (__findenv(name, (पूर्णांक)(np - name), &offset)) {
		क्रम (P = &environ[offset];; ++P)
			अगर (!(*P = *(P + 1)))
				अवरोध;
	}
	वापस (0);
}
#पूर्ण_अगर /* HAVE_UNSETENV */

#पूर्ण_अगर /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

