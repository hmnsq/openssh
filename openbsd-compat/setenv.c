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

#यदि !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

बाह्य वर्ण **environ;
#ifndef HAVE_SETENV
स्थिर वर्ण **lastenv;				/* last value of environ */
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
स्थिर वर्ण *
__findenv(अचर वर्ण *name, पूर्णाङ्क len, पूर्णाङ्क *offset)
{
	बाह्य वर्ण **environ;
	पूर्णाङ्क i;
	अचर वर्ण *np;
	वर्ण **p, *cp;

	यदि (name == रिक्त || environ == रिक्त)
		फर्काऊ (रिक्त);
	लागि (p = environ + *offset; (cp = *p) != रिक्त; ++p) {
		लागि (np = name, i = len; i && *cp; i--)
			यदि (*cp++ != *np++)
				रोक;
		यदि (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			फर्काऊ (cp);
		}
	}
	फर्काऊ (रिक्त);
}

#यदि 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
पूर्णाङ्क
putenv(वर्ण *str)
{
	वर्ण **P, *cp;
	माप_प्रकार cnt;
	पूर्णाङ्क offset = 0;

	लागि (cp = str; *cp && *cp != '='; ++cp)
		;
	यदि (*cp != '=') {
		त्रुटि_सं = EINVAL;
		फर्काऊ (-1);			/* missing `=' in string */
	}

	यदि (__findenv(str, (पूर्णाङ्क)(cp - str), &offset) != रिक्त) {
		environ[offset++] = str;
		/* could be set multiple times */
		जबसम्म (__findenv(str, (पूर्णाङ्क)(cp - str), &offset)) {
			लागि (P = &environ[offset];; ++P)
				यदि (!(*P = *(P + 1)))
					रोक;
		}
		फर्काऊ (0);
	}

	/* create new slot for string */
	लागि (P = environ; *P != रिक्त; P++)
		;
	cnt = P - environ;
	P = (वर्ण **)पुनः_स्मृति(lastenv, परिमाण(वर्ण *) * (cnt + 2));
	यदि (!P)
		फर्काऊ (-1);
	यदि (lastenv != environ)
		स_नकल(P, environ, cnt * परिमाण(वर्ण *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = रिक्त;
	फर्काऊ (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
पूर्णाङ्क
setenv(अचर वर्ण *name, अचर वर्ण *मान, पूर्णाङ्क rewrite)
{
	वर्ण *C, **P;
	अचर वर्ण *np;
	पूर्णाङ्क l_मान, offset = 0;

	लागि (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	यदि (*np) {
		त्रुटि_सं = EINVAL;
		फर्काऊ (-1);			/* has `=' in name */
	}
#endif

	l_मान = म_माप(मान);
	यदि ((C = __findenv(name, (पूर्णाङ्क)(np - name), &offset)) != रिक्त) {
		पूर्णाङ्क tmpoff = offset + 1;
		यदि (!rewrite)
			फर्काऊ (0);
#यदि 0 /* XXX - existing entry may not be writable */
		यदि (म_माप(C) >= l_मान) {	/* old larger; copy over */
			जबसम्म ((*C++ = *मान++))
				;
			फर्काऊ (0);
		}
#endif
		/* could be set multiple times */
		जबसम्म (__findenv(name, (पूर्णाङ्क)(np - name), &tmpoff)) {
			लागि (P = &environ[tmpoff];; ++P)
				यदि (!(*P = *(P + 1)))
					रोक;
		}
	} अन्यथा {					/* create new slot */
		माप_प्रकार cnt;

		लागि (P = environ; *P != रिक्त; P++)
			;
		cnt = P - environ;
		P = (वर्ण **)पुनः_स्मृति(lastenv, परिमाण(वर्ण *) * (cnt + 2));
		यदि (!P)
			फर्काऊ (-1);
		यदि (lastenv != environ)
			स_नकल(P, environ, cnt * परिमाण(वर्ण *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = रिक्त;
	}
	यदि (!(environ[offset] =			/* name + `=' + value */
	    दो_स्मृति((माप_प्रकार)((पूर्णाङ्क)(np - name) + l_मान + 2))))
		फर्काऊ (-1);
	लागि (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	लागि (*C++ = '='; (*C++ = *मान++); )
		;
	फर्काऊ (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
पूर्णाङ्क
unsetenv(अचर वर्ण *name)
{
	वर्ण **P;
	अचर वर्ण *np;
	पूर्णाङ्क offset = 0;

	यदि (!name || !*name) {
		त्रुटि_सं = EINVAL;
		फर्काऊ (-1);
	}
	लागि (np = name; *np && *np != '='; ++np)
		;
	यदि (*np) {
		त्रुटि_सं = EINVAL;
		फर्काऊ (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	जबसम्म (__findenv(name, (पूर्णाङ्क)(np - name), &offset)) {
		लागि (P = &environ[offset];; ++P)
			यदि (!(*P = *(P + 1)))
				रोक;
	}
	फर्काऊ (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

