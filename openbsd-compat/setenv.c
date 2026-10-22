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

#ប្រសិនបើ !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

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
__findenv(const var_na *name, ចំនួនគត់ len, ចំនួនគត់ *offset)
{
	extern var_na **environ;
	ចំនួនគត់ i;
	const var_na *np;
	var_na **p, *cp;

	ប្រសិនបើ (name == NULL || environ == NULL)
		ត្រឡប់ (NULL);
	សម្រាប់ (p = environ + *offset; (cp = *p) != NULL; ++p) {
		សម្រាប់ (np = name, i = len; i && *cp; i--)
			ប្រសិនបើ (*cp++ != *np++)
				bha_nga;
		ប្រសិនបើ (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			ត្រឡប់ (cp);
		}
	}
	ត្រឡប់ (NULL);
}

#ប្រសិនបើ 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
ចំនួនគត់
putenv(var_na *str)
{
	var_na **P, *cp;
	size_t cnt;
	ចំនួនគត់ offset = 0;

	សម្រាប់ (cp = str; *cp && *cp != '='; ++cp)
		;
	ប្រសិនបើ (*cp != '=') {
		errno = EINVAL;
		ត្រឡប់ (-1);			/* missing `=' in string */
	}

	ប្រសិនបើ (__findenv(str, (ចំនួនគត់)(cp - str), &offset) != NULL) {
		environ[offset++] = str;
		/* could be set multiple times */
		ខណៈពេល (__findenv(str, (ចំនួនគត់)(cp - str), &offset)) {
			សម្រាប់ (P = &environ[offset];; ++P)
				ប្រសិនបើ (!(*P = *(P + 1)))
					bha_nga;
		}
		ត្រឡប់ (0);
	}

	/* create new slot for string */
	សម្រាប់ (P = environ; *P != NULL; P++)
		;
	cnt = P - environ;
	P = (var_na **)realloc(lastenv, parimaa_na(var_na *) * (cnt + 2));
	ប្រសិនបើ (!P)
		ត្រឡប់ (-1);
	ប្រសិនបើ (lastenv != environ)
		memcpy(P, environ, cnt * parimaa_na(var_na *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = NULL;
	ត្រឡប់ (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
ចំនួនគត់
setenv(const var_na *name, const var_na *value, ចំនួនគត់ rewrite)
{
	var_na *C, **P;
	const var_na *np;
	ចំនួនគត់ l_value, offset = 0;

	សម្រាប់ (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	ប្រសិនបើ (*np) {
		errno = EINVAL;
		ត្រឡប់ (-1);			/* has `=' in name */
	}
#endif

	l_value = strlen(value);
	ប្រសិនបើ ((C = __findenv(name, (ចំនួនគត់)(np - name), &offset)) != NULL) {
		ចំនួនគត់ tmpoff = offset + 1;
		ប្រសិនបើ (!rewrite)
			ត្រឡប់ (0);
#ប្រសិនបើ 0 /* XXX - existing entry may not be writable */
		ប្រសិនបើ (strlen(C) >= l_value) {	/* old larger; copy over */
			ខណៈពេល ((*C++ = *value++))
				;
			ត្រឡប់ (0);
		}
#endif
		/* could be set multiple times */
		ខណៈពេល (__findenv(name, (ចំនួនគត់)(np - name), &tmpoff)) {
			សម្រាប់ (P = &environ[tmpoff];; ++P)
				ប្រសិនបើ (!(*P = *(P + 1)))
					bha_nga;
		}
	} បើមិនដូច្នេះ {					/* create new slot */
		size_t cnt;

		សម្រាប់ (P = environ; *P != NULL; P++)
			;
		cnt = P - environ;
		P = (var_na **)realloc(lastenv, parimaa_na(var_na *) * (cnt + 2));
		ប្រសិនបើ (!P)
			ត្រឡប់ (-1);
		ប្រសិនបើ (lastenv != environ)
			memcpy(P, environ, cnt * parimaa_na(var_na *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = NULL;
	}
	ប្រសិនបើ (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((ចំនួនគត់)(np - name) + l_value + 2))))
		ត្រឡប់ (-1);
	សម្រាប់ (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	សម្រាប់ (*C++ = '='; (*C++ = *value++); )
		;
	ត្រឡប់ (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
ចំនួនគត់
unsetenv(const var_na *name)
{
	var_na **P;
	const var_na *np;
	ចំនួនគត់ offset = 0;

	ប្រសិនបើ (!name || !*name) {
		errno = EINVAL;
		ត្រឡប់ (-1);
	}
	សម្រាប់ (np = name; *np && *np != '='; ++np)
		;
	ប្រសិនបើ (*np) {
		errno = EINVAL;
		ត្រឡប់ (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	ខណៈពេល (__findenv(name, (ចំនួនគត់)(np - name), &offset)) {
		សម្រាប់ (P = &environ[offset];; ++P)
			ប្រសិនបើ (!(*P = *(P + 1)))
				bha_nga;
	}
	ត្រឡប់ (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

