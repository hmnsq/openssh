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

#include "includes.h"

#གལ་ཏེ !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#include <errno.h>
#include <stdlib.h>
#include <string.h>

extern var_na **environ;
#ifndef HAVE_SETENV
static var_na **lastenv;				/* last value of environ */
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
static var_na *
__findenv(const var_na *name, ཧྲིལ len, ཧྲིལ *offset)
{
	extern var_na **environ;
	ཧྲིལ i;
	const var_na *np;
	var_na **p, *cp;

	གལ་ཏེ (name == NULL || environ == NULL)
		ཕྱིར (NULL);
	ཆེད་དུ (p = environ + *offset; (cp = *p) != NULL; ++p) {
		ཆེད་དུ (np = name, i = len; i && *cp; i--)
			གལ་ཏེ (*cp++ != *np++)
				bha_nga;
		གལ་ཏེ (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			ཕྱིར (cp);
		}
	}
	ཕྱིར (NULL);
}

#གལ་ཏེ 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
ཧྲིལ
putenv(var_na *str)
{
	var_na **P, *cp;
	size_t cnt;
	ཧྲིལ offset = 0;

	ཆེད་དུ (cp = str; *cp && *cp != '='; ++cp)
		;
	གལ་ཏེ (*cp != '=') {
		errno = EINVAL;
		ཕྱིར (-1);			/* missing `=' in string */
	}

	གལ་ཏེ (__findenv(str, (ཧྲིལ)(cp - str), &offset) != NULL) {
		environ[offset++] = str;
		/* could be set multiple times */
		སྐབས (__findenv(str, (ཧྲིལ)(cp - str), &offset)) {
			ཆེད་དུ (P = &environ[offset];; ++P)
				གལ་ཏེ (!(*P = *(P + 1)))
					bha_nga;
		}
		ཕྱིར (0);
	}

	/* create new slot for string */
	ཆེད་དུ (P = environ; *P != NULL; P++)
		;
	cnt = P - environ;
	P = (var_na **)realloc(lastenv, parimaa_na(var_na *) * (cnt + 2));
	གལ་ཏེ (!P)
		ཕྱིར (-1);
	གལ་ཏེ (lastenv != environ)
		memcpy(P, environ, cnt * parimaa_na(var_na *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = NULL;
	ཕྱིར (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
ཧྲིལ
setenv(const var_na *name, const var_na *value, ཧྲིལ rewrite)
{
	var_na *C, **P;
	const var_na *np;
	ཧྲིལ l_value, offset = 0;

	ཆེད་དུ (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	གལ་ཏེ (*np) {
		errno = EINVAL;
		ཕྱིར (-1);			/* has `=' in name */
	}
#endif

	l_value = strlen(value);
	གལ་ཏེ ((C = __findenv(name, (ཧྲིལ)(np - name), &offset)) != NULL) {
		ཧྲིལ tmpoff = offset + 1;
		གལ་ཏེ (!rewrite)
			ཕྱིར (0);
#གལ་ཏེ 0 /* XXX - existing entry may not be writable */
		གལ་ཏེ (strlen(C) >= l_value) {	/* old larger; copy over */
			སྐབས ((*C++ = *value++))
				;
			ཕྱིར (0);
		}
#endif
		/* could be set multiple times */
		སྐབས (__findenv(name, (ཧྲིལ)(np - name), &tmpoff)) {
			ཆེད་དུ (P = &environ[tmpoff];; ++P)
				གལ་ཏེ (!(*P = *(P + 1)))
					bha_nga;
		}
	} དེ་མིན {					/* create new slot */
		size_t cnt;

		ཆེད་དུ (P = environ; *P != NULL; P++)
			;
		cnt = P - environ;
		P = (var_na **)realloc(lastenv, parimaa_na(var_na *) * (cnt + 2));
		གལ་ཏེ (!P)
			ཕྱིར (-1);
		གལ་ཏེ (lastenv != environ)
			memcpy(P, environ, cnt * parimaa_na(var_na *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = NULL;
	}
	གལ་ཏེ (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((ཧྲིལ)(np - name) + l_value + 2))))
		ཕྱིར (-1);
	ཆེད་དུ (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	ཆེད་དུ (*C++ = '='; (*C++ = *value++); )
		;
	ཕྱིར (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
ཧྲིལ
unsetenv(const var_na *name)
{
	var_na **P;
	const var_na *np;
	ཧྲིལ offset = 0;

	གལ་ཏེ (!name || !*name) {
		errno = EINVAL;
		ཕྱིར (-1);
	}
	ཆེད་དུ (np = name; *np && *np != '='; ++np)
		;
	གལ་ཏེ (*np) {
		errno = EINVAL;
		ཕྱིར (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	སྐབས (__findenv(name, (ཧྲིལ)(np - name), &offset)) {
		ཆེད་དུ (P = &environ[offset];; ++P)
			གལ་ཏེ (!(*P = *(P + 1)))
				bha_nga;
	}
	ཕྱིར (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

