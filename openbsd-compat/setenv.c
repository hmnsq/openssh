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

#만약 !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

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
__findenv(const char *name, 정수 len, 정수 *offset)
{
	extern char **environ;
	정수 i;
	const char *np;
	char **p, *cp;

	만약 (name == NULL || environ == NULL)
		반환 (NULL);
	위해 (p = environ + *offset; (cp = *p) != NULL; ++p) {
		위해 (np = name, i = len; i && *cp; i--)
			만약 (*cp++ != *np++)
				break;
		만약 (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			반환 (cp);
		}
	}
	반환 (NULL);
}

#만약 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
정수
putenv(char *str)
{
	char **P, *cp;
	size_t cnt;
	정수 offset = 0;

	위해 (cp = str; *cp && *cp != '='; ++cp)
		;
	만약 (*cp != '=') {
		errno = EINVAL;
		반환 (-1);			/* missing `=' in string */
	}

	만약 (__findenv(str, (정수)(cp - str), &offset) != NULL) {
		environ[offset++] = str;
		/* could be set multiple times */
		동안 (__findenv(str, (정수)(cp - str), &offset)) {
			위해 (P = &environ[offset];; ++P)
				만약 (!(*P = *(P + 1)))
					break;
		}
		반환 (0);
	}

	/* create new slot for string */
	위해 (P = environ; *P != NULL; P++)
		;
	cnt = P - environ;
	P = (char **)realloc(lastenv, sizeof(char *) * (cnt + 2));
	만약 (!P)
		반환 (-1);
	만약 (lastenv != environ)
		memcpy(P, environ, cnt * sizeof(char *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = NULL;
	반환 (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
정수
setenv(const char *name, const char *value, 정수 rewrite)
{
	char *C, **P;
	const char *np;
	정수 l_value, offset = 0;

	위해 (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	만약 (*np) {
		errno = EINVAL;
		반환 (-1);			/* has `=' in name */
	}
#endif

	l_value = strlen(value);
	만약 ((C = __findenv(name, (정수)(np - name), &offset)) != NULL) {
		정수 tmpoff = offset + 1;
		만약 (!rewrite)
			반환 (0);
#만약 0 /* XXX - existing entry may not be writable */
		만약 (strlen(C) >= l_value) {	/* old larger; copy over */
			동안 ((*C++ = *value++))
				;
			반환 (0);
		}
#endif
		/* could be set multiple times */
		동안 (__findenv(name, (정수)(np - name), &tmpoff)) {
			위해 (P = &environ[tmpoff];; ++P)
				만약 (!(*P = *(P + 1)))
					break;
		}
	} 아니면 {					/* create new slot */
		size_t cnt;

		위해 (P = environ; *P != NULL; P++)
			;
		cnt = P - environ;
		P = (char **)realloc(lastenv, sizeof(char *) * (cnt + 2));
		만약 (!P)
			반환 (-1);
		만약 (lastenv != environ)
			memcpy(P, environ, cnt * sizeof(char *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = NULL;
	}
	만약 (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((정수)(np - name) + l_value + 2))))
		반환 (-1);
	위해 (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	위해 (*C++ = '='; (*C++ = *value++); )
		;
	반환 (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
정수
unsetenv(const char *name)
{
	char **P;
	const char *np;
	정수 offset = 0;

	만약 (!name || !*name) {
		errno = EINVAL;
		반환 (-1);
	}
	위해 (np = name; *np && *np != '='; ++np)
		;
	만약 (*np) {
		errno = EINVAL;
		반환 (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	동안 (__findenv(name, (정수)(np - name), &offset)) {
		위해 (P = &environ[offset];; ++P)
			만약 (!(*P = *(P + 1)))
				break;
	}
	반환 (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

