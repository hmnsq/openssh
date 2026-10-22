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

#အကယ်၍ !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

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
__findenv(const var_na *name, ကိန်းပြည့် len, ကိန်းပြည့် *offset)
{
	extern var_na **environ;
	ကိန်းပြည့် i;
	const var_na *np;
	var_na **p, *cp;

	အကယ်၍ (name == NULL || environ == NULL)
		ပြန်ပေး (NULL);
	အတွက် (p = environ + *offset; (cp = *p) != NULL; ++p) {
		အတွက် (np = name, i = len; i && *cp; i--)
			အကယ်၍ (*cp++ != *np++)
				bha_nga;
		အကယ်၍ (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			ပြန်ပေး (cp);
		}
	}
	ပြန်ပေး (NULL);
}

#အကယ်၍ 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
ကိန်းပြည့်
putenv(var_na *str)
{
	var_na **P, *cp;
	size_t cnt;
	ကိန်းပြည့် offset = 0;

	အတွက် (cp = str; *cp && *cp != '='; ++cp)
		;
	အကယ်၍ (*cp != '=') {
		errno = EINVAL;
		ပြန်ပေး (-1);			/* missing `=' in string */
	}

	အကယ်၍ (__findenv(str, (ကိန်းပြည့်)(cp - str), &offset) != NULL) {
		environ[offset++] = str;
		/* could be set multiple times */
		နေစဉ် (__findenv(str, (ကိန်းပြည့်)(cp - str), &offset)) {
			အတွက် (P = &environ[offset];; ++P)
				အကယ်၍ (!(*P = *(P + 1)))
					bha_nga;
		}
		ပြန်ပေး (0);
	}

	/* create new slot for string */
	အတွက် (P = environ; *P != NULL; P++)
		;
	cnt = P - environ;
	P = (var_na **)realloc(lastenv, parimaa_na(var_na *) * (cnt + 2));
	အကယ်၍ (!P)
		ပြန်ပေး (-1);
	အကယ်၍ (lastenv != environ)
		memcpy(P, environ, cnt * parimaa_na(var_na *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = NULL;
	ပြန်ပေး (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
ကိန်းပြည့်
setenv(const var_na *name, const var_na *value, ကိန်းပြည့် rewrite)
{
	var_na *C, **P;
	const var_na *np;
	ကိန်းပြည့် l_value, offset = 0;

	အတွက် (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	အကယ်၍ (*np) {
		errno = EINVAL;
		ပြန်ပေး (-1);			/* has `=' in name */
	}
#endif

	l_value = strlen(value);
	အကယ်၍ ((C = __findenv(name, (ကိန်းပြည့်)(np - name), &offset)) != NULL) {
		ကိန်းပြည့် tmpoff = offset + 1;
		အကယ်၍ (!rewrite)
			ပြန်ပေး (0);
#အကယ်၍ 0 /* XXX - existing entry may not be writable */
		အကယ်၍ (strlen(C) >= l_value) {	/* old larger; copy over */
			နေစဉ် ((*C++ = *value++))
				;
			ပြန်ပေး (0);
		}
#endif
		/* could be set multiple times */
		နေစဉ် (__findenv(name, (ကိန်းပြည့်)(np - name), &tmpoff)) {
			အတွက် (P = &environ[tmpoff];; ++P)
				အကယ်၍ (!(*P = *(P + 1)))
					bha_nga;
		}
	} မဟုတ်ပါက {					/* create new slot */
		size_t cnt;

		အတွက် (P = environ; *P != NULL; P++)
			;
		cnt = P - environ;
		P = (var_na **)realloc(lastenv, parimaa_na(var_na *) * (cnt + 2));
		အကယ်၍ (!P)
			ပြန်ပေး (-1);
		အကယ်၍ (lastenv != environ)
			memcpy(P, environ, cnt * parimaa_na(var_na *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = NULL;
	}
	အကယ်၍ (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((ကိန်းပြည့်)(np - name) + l_value + 2))))
		ပြန်ပေး (-1);
	အတွက် (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	အတွက် (*C++ = '='; (*C++ = *value++); )
		;
	ပြန်ပေး (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
ကိန်းပြည့်
unsetenv(const var_na *name)
{
	var_na **P;
	const var_na *np;
	ကိန်းပြည့် offset = 0;

	အကယ်၍ (!name || !*name) {
		errno = EINVAL;
		ပြန်ပေး (-1);
	}
	အတွက် (np = name; *np && *np != '='; ++np)
		;
	အကယ်၍ (*np) {
		errno = EINVAL;
		ပြန်ပေး (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	နေစဉ် (__findenv(name, (ကိန်းပြည့်)(np - name), &offset)) {
		အတွက် (P = &environ[offset];; ++P)
			အကယ်၍ (!(*P = *(P + 1)))
				bha_nga;
	}
	ပြန်ပေး (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

