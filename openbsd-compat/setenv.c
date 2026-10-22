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

#если !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

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
__findenv(const char *name, целое len, целое *offset)
{
	extern char **environ;
	целое i;
	const char *np;
	char **p, *cp;

	если (name == NULL || environ == NULL)
		вернуть (NULL);
	для (p = environ + *offset; (cp = *p) != NULL; ++p) {
		для (np = name, i = len; i && *cp; i--)
			если (*cp++ != *np++)
				break;
		если (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			вернуть (cp);
		}
	}
	вернуть (NULL);
}

#если 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
целое
putenv(char *str)
{
	char **P, *cp;
	size_t cnt;
	целое offset = 0;

	для (cp = str; *cp && *cp != '='; ++cp)
		;
	если (*cp != '=') {
		errno = EINVAL;
		вернуть (-1);			/* missing `=' in string */
	}

	если (__findenv(str, (целое)(cp - str), &offset) != NULL) {
		environ[offset++] = str;
		/* could be set multiple times */
		пока (__findenv(str, (целое)(cp - str), &offset)) {
			для (P = &environ[offset];; ++P)
				если (!(*P = *(P + 1)))
					break;
		}
		вернуть (0);
	}

	/* create new slot for string */
	для (P = environ; *P != NULL; P++)
		;
	cnt = P - environ;
	P = (char **)realloc(lastenv, sizeof(char *) * (cnt + 2));
	если (!P)
		вернуть (-1);
	если (lastenv != environ)
		memcpy(P, environ, cnt * sizeof(char *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = NULL;
	вернуть (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
целое
setenv(const char *name, const char *value, целое rewrite)
{
	char *C, **P;
	const char *np;
	целое l_value, offset = 0;

	для (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	если (*np) {
		errno = EINVAL;
		вернуть (-1);			/* has `=' in name */
	}
#endif

	l_value = strlen(value);
	если ((C = __findenv(name, (целое)(np - name), &offset)) != NULL) {
		целое tmpoff = offset + 1;
		если (!rewrite)
			вернуть (0);
#если 0 /* XXX - existing entry may not be writable */
		если (strlen(C) >= l_value) {	/* old larger; copy over */
			пока ((*C++ = *value++))
				;
			вернуть (0);
		}
#endif
		/* could be set multiple times */
		пока (__findenv(name, (целое)(np - name), &tmpoff)) {
			для (P = &environ[tmpoff];; ++P)
				если (!(*P = *(P + 1)))
					break;
		}
	} иначе {					/* create new slot */
		size_t cnt;

		для (P = environ; *P != NULL; P++)
			;
		cnt = P - environ;
		P = (char **)realloc(lastenv, sizeof(char *) * (cnt + 2));
		если (!P)
			вернуть (-1);
		если (lastenv != environ)
			memcpy(P, environ, cnt * sizeof(char *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = NULL;
	}
	если (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((целое)(np - name) + l_value + 2))))
		вернуть (-1);
	для (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	для (*C++ = '='; (*C++ = *value++); )
		;
	вернуть (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
целое
unsetenv(const char *name)
{
	char **P;
	const char *np;
	целое offset = 0;

	если (!name || !*name) {
		errno = EINVAL;
		вернуть (-1);
	}
	для (np = name; *np && *np != '='; ++np)
		;
	если (*np) {
		errno = EINVAL;
		вернуть (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	пока (__findenv(name, (целое)(np - name), &offset)) {
		для (P = &environ[offset];; ++P)
			если (!(*P = *(P + 1)))
				break;
	}
	вернуть (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

