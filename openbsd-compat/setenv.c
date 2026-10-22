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
#यदि_अपरिभाषितम् HAVE_SETENV
स्थिर वर्ण **lastenv;				/* last value of environ */
#यदि_अन्तः

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
__findenv(ध्रुव वर्ण *name, पूर्णाङ्क len, पूर्णाङ्क *विस्थापनम्)
{
	बाह्य वर्ण **environ;
	पूर्णाङ्क i;
	ध्रुव वर्ण *np;
	वर्ण **p, *cp;

	यदि (name == रिक्त || environ == रिक्त)
		प्रत्यागम (रिक्त);
	प्रति (p = environ + *विस्थापनम्; (cp = *p) != रिक्त; ++p) {
		प्रति (np = name, i = len; i && *cp; i--)
			यदि (*cp++ != *np++)
				भङ्ग;
		यदि (i == 0 && *cp++ == '=') {
			*विस्थापनम् = p - environ;
			प्रत्यागम (cp);
		}
	}
	प्रत्यागम (रिक्त);
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
	आकार_t cnt;
	पूर्णाङ्क विस्थापनम् = 0;

	प्रति (cp = str; *cp && *cp != '='; ++cp)
		;
	यदि (*cp != '=') {
		errno = EINVAL;
		प्रत्यागम (-1);			/* missing `=' in string */
	}

	यदि (__findenv(str, (पूर्णाङ्क)(cp - str), &विस्थापनम्) != रिक्त) {
		environ[विस्थापनम्++] = str;
		/* could be set multiple times */
		यावत् (__findenv(str, (पूर्णाङ्क)(cp - str), &विस्थापनम्)) {
			प्रति (P = &environ[विस्थापनम्];; ++P)
				यदि (!(*P = *(P + 1)))
					भङ्ग;
		}
		प्रत्यागम (0);
	}

	/* create new slot for string */
	प्रति (P = environ; *P != रिक्त; P++)
		;
	cnt = P - environ;
	P = (वर्ण **)realloc(lastenv, परिमाण(वर्ण *) * (cnt + 2));
	यदि (!P)
		प्रत्यागम (-1);
	यदि (lastenv != environ)
		स्मृतिं_प्रतिलिख(P, environ, cnt * परिमाण(वर्ण *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = रिक्त;
	प्रत्यागम (0);
}

#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
पूर्णाङ्क
setenv(ध्रुव वर्ण *name, ध्रुव वर्ण *मानम्, पूर्णाङ्क rewrite)
{
	वर्ण *C, **P;
	ध्रुव वर्ण *np;
	पूर्णाङ्क l_मानम्, विस्थापनम् = 0;

	प्रति (np = name; *np && *np != '='; ++np)
		;
#यदि_परिभाषितम् notyet
	यदि (*np) {
		errno = EINVAL;
		प्रत्यागम (-1);			/* has `=' in name */
	}
#यदि_अन्तः

	l_मानम् = वाक्यदैर्घ्यम्(मानम्);
	यदि ((C = __findenv(name, (पूर्णाङ्क)(np - name), &विस्थापनम्)) != रिक्त) {
		पूर्णाङ्क tmpoff = विस्थापनम् + 1;
		यदि (!rewrite)
			प्रत्यागम (0);
#यदि 0 /* XXX - existing entry may not be writable */
		यदि (वाक्यदैर्घ्यम्(C) >= l_मानम्) {	/* old larger; copy over */
			यावत् ((*C++ = *मानम्++))
				;
			प्रत्यागम (0);
		}
#यदि_अन्तः
		/* could be set multiple times */
		यावत् (__findenv(name, (पूर्णाङ्क)(np - name), &tmpoff)) {
			प्रति (P = &environ[tmpoff];; ++P)
				यदि (!(*P = *(P + 1)))
					भङ्ग;
		}
	} अन्यथा {					/* create new slot */
		आकार_t cnt;

		प्रति (P = environ; *P != रिक्त; P++)
			;
		cnt = P - environ;
		P = (वर्ण **)realloc(lastenv, परिमाण(वर्ण *) * (cnt + 2));
		यदि (!P)
			प्रत्यागम (-1);
		यदि (lastenv != environ)
			स्मृतिं_प्रतिलिख(P, environ, cnt * परिमाण(वर्ण *));
		lastenv = environ = P;
		विस्थापनम् = cnt;
		environ[cnt + 1] = रिक्त;
	}
	यदि (!(environ[विस्थापनम्] =			/* name + `=' + value */
	    स्मृतिं_देहि((आकार_t)((पूर्णाङ्क)(np - name) + l_मानम् + 2))))
		प्रत्यागम (-1);
	प्रति (C = environ[विस्थापनम्]; (*C = *name++) && *C != '='; ++C)
		;
	प्रति (*C++ = '='; (*C++ = *मानम्++); )
		;
	प्रत्यागम (0);
}

#यदि_अन्तः /* HAVE_SETENV */

#यदि_अपरिभाषितम् HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
पूर्णाङ्क
unsetenv(ध्रुव वर्ण *name)
{
	वर्ण **P;
	ध्रुव वर्ण *np;
	पूर्णाङ्क विस्थापनम् = 0;

	यदि (!name || !*name) {
		errno = EINVAL;
		प्रत्यागम (-1);
	}
	प्रति (np = name; *np && *np != '='; ++np)
		;
	यदि (*np) {
		errno = EINVAL;
		प्रत्यागम (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	यावत् (__findenv(name, (पूर्णाङ्क)(np - name), &विस्थापनम्)) {
		प्रति (P = &environ[विस्थापनम्];; ++P)
			यदि (!(*P = *(P + 1)))
				भङ्ग;
	}
	प्रत्यागम (0);
}
#यदि_अन्तः /* HAVE_UNSETENV */

#यदि_अन्तः /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

