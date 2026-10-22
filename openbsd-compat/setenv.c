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

#ᬬᬾᬦ᭄ !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

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
__findenv(const var_na *name, puur_naa_nka len, puur_naa_nka *offset)
{
	extern var_na **environ;
	puur_naa_nka i;
	const var_na *np;
	var_na **p, *cp;

	ᬬᬾᬦ᭄ (name == NULL || environ == NULL)
		ᬯᬮᬶ (NULL);
	for (p = environ + *offset; (cp = *p) != NULL; ++p) {
		for (np = name, i = len; i && *cp; i--)
			ᬬᬾᬦ᭄ (*cp++ != *np++)
				bha_nga;
		ᬬᬾᬦ᭄ (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			ᬯᬮᬶ (cp);
		}
	}
	ᬯᬮᬶ (NULL);
}

#ᬬᬾᬦ᭄ 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
puur_naa_nka
putenv(var_na *str)
{
	var_na **P, *cp;
	size_t cnt;
	puur_naa_nka offset = 0;

	for (cp = str; *cp && *cp != '='; ++cp)
		;
	ᬬᬾᬦ᭄ (*cp != '=') {
		errno = EINVAL;
		ᬯᬮᬶ (-1);			/* missing `=' in string */
	}

	ᬬᬾᬦ᭄ (__findenv(str, (puur_naa_nka)(cp - str), &offset) != NULL) {
		environ[offset++] = str;
		/* could be set multiple times */
		ᬲᭂᬤᭂᬮ (__findenv(str, (puur_naa_nka)(cp - str), &offset)) {
			for (P = &environ[offset];; ++P)
				ᬬᬾᬦ᭄ (!(*P = *(P + 1)))
					bha_nga;
		}
		ᬯᬮᬶ (0);
	}

	/* create new slot for string */
	for (P = environ; *P != NULL; P++)
		;
	cnt = P - environ;
	P = (var_na **)realloc(lastenv, parimaa_na(var_na *) * (cnt + 2));
	ᬬᬾᬦ᭄ (!P)
		ᬯᬮᬶ (-1);
	ᬬᬾᬦ᭄ (lastenv != environ)
		memcpy(P, environ, cnt * parimaa_na(var_na *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = NULL;
	ᬯᬮᬶ (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
puur_naa_nka
setenv(const var_na *name, const var_na *value, puur_naa_nka rewrite)
{
	var_na *C, **P;
	const var_na *np;
	puur_naa_nka l_value, offset = 0;

	for (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	ᬬᬾᬦ᭄ (*np) {
		errno = EINVAL;
		ᬯᬮᬶ (-1);			/* has `=' in name */
	}
#endif

	l_value = strlen(value);
	ᬬᬾᬦ᭄ ((C = __findenv(name, (puur_naa_nka)(np - name), &offset)) != NULL) {
		puur_naa_nka tmpoff = offset + 1;
		ᬬᬾᬦ᭄ (!rewrite)
			ᬯᬮᬶ (0);
#ᬬᬾᬦ᭄ 0 /* XXX - existing entry may not be writable */
		ᬬᬾᬦ᭄ (strlen(C) >= l_value) {	/* old larger; copy over */
			ᬲᭂᬤᭂᬮ ((*C++ = *value++))
				;
			ᬯᬮᬶ (0);
		}
#endif
		/* could be set multiple times */
		ᬲᭂᬤᭂᬮ (__findenv(name, (puur_naa_nka)(np - name), &tmpoff)) {
			for (P = &environ[tmpoff];; ++P)
				ᬬᬾᬦ᭄ (!(*P = *(P + 1)))
					bha_nga;
		}
	} ᬮᬶᬬ {					/* create new slot */
		size_t cnt;

		for (P = environ; *P != NULL; P++)
			;
		cnt = P - environ;
		P = (var_na **)realloc(lastenv, parimaa_na(var_na *) * (cnt + 2));
		ᬬᬾᬦ᭄ (!P)
			ᬯᬮᬶ (-1);
		ᬬᬾᬦ᭄ (lastenv != environ)
			memcpy(P, environ, cnt * parimaa_na(var_na *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = NULL;
	}
	ᬬᬾᬦ᭄ (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((puur_naa_nka)(np - name) + l_value + 2))))
		ᬯᬮᬶ (-1);
	for (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	for (*C++ = '='; (*C++ = *value++); )
		;
	ᬯᬮᬶ (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
puur_naa_nka
unsetenv(const var_na *name)
{
	var_na **P;
	const var_na *np;
	puur_naa_nka offset = 0;

	ᬬᬾᬦ᭄ (!name || !*name) {
		errno = EINVAL;
		ᬯᬮᬶ (-1);
	}
	for (np = name; *np && *np != '='; ++np)
		;
	ᬬᬾᬦ᭄ (*np) {
		errno = EINVAL;
		ᬯᬮᬶ (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	ᬲᭂᬤᭂᬮ (__findenv(name, (puur_naa_nka)(np - name), &offset)) {
		for (P = &environ[offset];; ++P)
			ᬬᬾᬦ᭄ (!(*P = *(P + 1)))
				bha_nga;
	}
	ᬯᬮᬶ (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

