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

#якщо !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#include <errno.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;
#ifndef HAVE_SETENV
static char **lastenv;				/* last value of environ */
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
static char *
__findenv(const char *name, ціле len, ціле *offset)
{
	extern char **environ;
	ціле i;
	const char *np;
	char **p, *cp;

	якщо (name == NULL || environ == NULL)
		повернути (NULL);
	для (p = environ + *offset; (cp = *p) != NULL; ++p) {
		для (np = name, i = len; i && *cp; i--)
			якщо (*cp++ != *np++)
				break;
		якщо (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			повернути (cp);
		}
	}
	повернути (NULL);
}

#якщо 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
ціле
putenv(char *str)
{
	char **P, *cp;
	size_t cnt;
	ціле offset = 0;

	для (cp = str; *cp && *cp != '='; ++cp)
		;
	якщо (*cp != '=') {
		errno = EINVAL;
		повернути (-1);			/* missing `=' in string */
	}

	якщо (__findenv(str, (ціле)(cp - str), &offset) != NULL) {
		environ[offset++] = str;
		/* could be set multiple times */
		поки (__findenv(str, (ціле)(cp - str), &offset)) {
			для (P = &environ[offset];; ++P)
				якщо (!(*P = *(P + 1)))
					break;
		}
		повернути (0);
	}

	/* create new slot for string */
	для (P = environ; *P != NULL; P++)
		;
	cnt = P - environ;
	P = (char **)realloc(lastenv, sizeof(char *) * (cnt + 2));
	якщо (!P)
		повернути (-1);
	якщо (lastenv != environ)
		memcpy(P, environ, cnt * sizeof(char *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = NULL;
	повернути (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
ціле
setenv(const char *name, const char *value, ціле rewrite)
{
	char *C, **P;
	const char *np;
	ціле l_value, offset = 0;

	для (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	якщо (*np) {
		errno = EINVAL;
		повернути (-1);			/* has `=' in name */
	}
#endif

	l_value = strlen(value);
	якщо ((C = __findenv(name, (ціле)(np - name), &offset)) != NULL) {
		ціле tmpoff = offset + 1;
		якщо (!rewrite)
			повернути (0);
#якщо 0 /* XXX - existing entry may not be writable */
		якщо (strlen(C) >= l_value) {	/* old larger; copy over */
			поки ((*C++ = *value++))
				;
			повернути (0);
		}
#endif
		/* could be set multiple times */
		поки (__findenv(name, (ціле)(np - name), &tmpoff)) {
			для (P = &environ[tmpoff];; ++P)
				якщо (!(*P = *(P + 1)))
					break;
		}
	} інакше {					/* create new slot */
		size_t cnt;

		для (P = environ; *P != NULL; P++)
			;
		cnt = P - environ;
		P = (char **)realloc(lastenv, sizeof(char *) * (cnt + 2));
		якщо (!P)
			повернути (-1);
		якщо (lastenv != environ)
			memcpy(P, environ, cnt * sizeof(char *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = NULL;
	}
	якщо (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((ціле)(np - name) + l_value + 2))))
		повернути (-1);
	для (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	для (*C++ = '='; (*C++ = *value++); )
		;
	повернути (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
ціле
unsetenv(const char *name)
{
	char **P;
	const char *np;
	ціле offset = 0;

	якщо (!name || !*name) {
		errno = EINVAL;
		повернути (-1);
	}
	для (np = name; *np && *np != '='; ++np)
		;
	якщо (*np) {
		errno = EINVAL;
		повернути (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	поки (__findenv(name, (ціле)(np - name), &offset)) {
		для (P = &environ[offset];; ++P)
			якщо (!(*P = *(P + 1)))
				break;
	}
	повернути (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

