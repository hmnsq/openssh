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

#nếu !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

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
__findenv(const char *name, số_nguyên len, số_nguyên *offset)
{
	extern char **environ;
	số_nguyên i;
	const char *np;
	char **p, *cp;

	nếu (name == NULL || environ == NULL)
		trả_về (NULL);
	cho (p = environ + *offset; (cp = *p) != NULL; ++p) {
		cho (np = name, i = len; i && *cp; i--)
			nếu (*cp++ != *np++)
				break;
		nếu (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			trả_về (cp);
		}
	}
	trả_về (NULL);
}

#nếu 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
số_nguyên
putenv(char *str)
{
	char **P, *cp;
	size_t cnt;
	số_nguyên offset = 0;

	cho (cp = str; *cp && *cp != '='; ++cp)
		;
	nếu (*cp != '=') {
		errno = EINVAL;
		trả_về (-1);			/* missing `=' in string */
	}

	nếu (__findenv(str, (số_nguyên)(cp - str), &offset) != NULL) {
		environ[offset++] = str;
		/* could be set multiple times */
		trong_khi (__findenv(str, (số_nguyên)(cp - str), &offset)) {
			cho (P = &environ[offset];; ++P)
				nếu (!(*P = *(P + 1)))
					break;
		}
		trả_về (0);
	}

	/* create new slot for string */
	cho (P = environ; *P != NULL; P++)
		;
	cnt = P - environ;
	P = (char **)realloc(lastenv, sizeof(char *) * (cnt + 2));
	nếu (!P)
		trả_về (-1);
	nếu (lastenv != environ)
		memcpy(P, environ, cnt * sizeof(char *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = NULL;
	trả_về (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
số_nguyên
setenv(const char *name, const char *value, số_nguyên rewrite)
{
	char *C, **P;
	const char *np;
	số_nguyên l_value, offset = 0;

	cho (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	nếu (*np) {
		errno = EINVAL;
		trả_về (-1);			/* has `=' in name */
	}
#endif

	l_value = strlen(value);
	nếu ((C = __findenv(name, (số_nguyên)(np - name), &offset)) != NULL) {
		số_nguyên tmpoff = offset + 1;
		nếu (!rewrite)
			trả_về (0);
#nếu 0 /* XXX - existing entry may not be writable */
		nếu (strlen(C) >= l_value) {	/* old larger; copy over */
			trong_khi ((*C++ = *value++))
				;
			trả_về (0);
		}
#endif
		/* could be set multiple times */
		trong_khi (__findenv(name, (số_nguyên)(np - name), &tmpoff)) {
			cho (P = &environ[tmpoff];; ++P)
				nếu (!(*P = *(P + 1)))
					break;
		}
	} không_thì {					/* create new slot */
		size_t cnt;

		cho (P = environ; *P != NULL; P++)
			;
		cnt = P - environ;
		P = (char **)realloc(lastenv, sizeof(char *) * (cnt + 2));
		nếu (!P)
			trả_về (-1);
		nếu (lastenv != environ)
			memcpy(P, environ, cnt * sizeof(char *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = NULL;
	}
	nếu (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((số_nguyên)(np - name) + l_value + 2))))
		trả_về (-1);
	cho (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	cho (*C++ = '='; (*C++ = *value++); )
		;
	trả_về (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
số_nguyên
unsetenv(const char *name)
{
	char **P;
	const char *np;
	số_nguyên offset = 0;

	nếu (!name || !*name) {
		errno = EINVAL;
		trả_về (-1);
	}
	cho (np = name; *np && *np != '='; ++np)
		;
	nếu (*np) {
		errno = EINVAL;
		trả_về (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	trong_khi (__findenv(name, (số_nguyên)(np - name), &offset)) {
		cho (P = &environ[offset];; ++P)
			nếu (!(*P = *(P + 1)))
				break;
	}
	trả_về (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

