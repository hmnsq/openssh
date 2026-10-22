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

#ако !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

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
__findenv(const char *name, цео len, цео *offset)
{
	extern char **environ;
	цео i;
	const char *np;
	char **p, *cp;

	ако (name == NULL || environ == NULL)
		врати (NULL);
	за (p = environ + *offset; (cp = *p) != NULL; ++p) {
		за (np = name, i = len; i && *cp; i--)
			ако (*cp++ != *np++)
				break;
		ако (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			врати (cp);
		}
	}
	врати (NULL);
}

#ако 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
цео
putenv(char *str)
{
	char **P, *cp;
	size_t cnt;
	цео offset = 0;

	за (cp = str; *cp && *cp != '='; ++cp)
		;
	ако (*cp != '=') {
		errno = EINVAL;
		врати (-1);			/* missing `=' in string */
	}

	ако (__findenv(str, (цео)(cp - str), &offset) != NULL) {
		environ[offset++] = str;
		/* could be set multiple times */
		док (__findenv(str, (цео)(cp - str), &offset)) {
			за (P = &environ[offset];; ++P)
				ако (!(*P = *(P + 1)))
					break;
		}
		врати (0);
	}

	/* create new slot for string */
	за (P = environ; *P != NULL; P++)
		;
	cnt = P - environ;
	P = (char **)realloc(lastenv, sizeof(char *) * (cnt + 2));
	ако (!P)
		врати (-1);
	ако (lastenv != environ)
		memcpy(P, environ, cnt * sizeof(char *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = NULL;
	врати (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
цео
setenv(const char *name, const char *value, цео rewrite)
{
	char *C, **P;
	const char *np;
	цео l_value, offset = 0;

	за (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	ако (*np) {
		errno = EINVAL;
		врати (-1);			/* has `=' in name */
	}
#endif

	l_value = strlen(value);
	ако ((C = __findenv(name, (цео)(np - name), &offset)) != NULL) {
		цео tmpoff = offset + 1;
		ако (!rewrite)
			врати (0);
#ако 0 /* XXX - existing entry may not be writable */
		ако (strlen(C) >= l_value) {	/* old larger; copy over */
			док ((*C++ = *value++))
				;
			врати (0);
		}
#endif
		/* could be set multiple times */
		док (__findenv(name, (цео)(np - name), &tmpoff)) {
			за (P = &environ[tmpoff];; ++P)
				ако (!(*P = *(P + 1)))
					break;
		}
	} инако {					/* create new slot */
		size_t cnt;

		за (P = environ; *P != NULL; P++)
			;
		cnt = P - environ;
		P = (char **)realloc(lastenv, sizeof(char *) * (cnt + 2));
		ако (!P)
			врати (-1);
		ако (lastenv != environ)
			memcpy(P, environ, cnt * sizeof(char *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = NULL;
	}
	ако (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((цео)(np - name) + l_value + 2))))
		врати (-1);
	за (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	за (*C++ = '='; (*C++ = *value++); )
		;
	врати (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
цео
unsetenv(const char *name)
{
	char **P;
	const char *np;
	цео offset = 0;

	ако (!name || !*name) {
		errno = EINVAL;
		врати (-1);
	}
	за (np = name; *np && *np != '='; ++np)
		;
	ако (*np) {
		errno = EINVAL;
		врати (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	док (__findenv(name, (цео)(np - name), &offset)) {
		за (P = &environ[offset];; ++P)
			ако (!(*P = *(P + 1)))
				break;
	}
	врати (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

