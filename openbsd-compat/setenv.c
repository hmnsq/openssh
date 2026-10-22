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

#නම් !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

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
__findenv(const var_na *name, පූර්ණ_සංඛ්‍යා len, පූර්ණ_සංඛ්‍යා *offset)
{
	extern var_na **environ;
	පූර්ණ_සංඛ්‍යා i;
	const var_na *np;
	var_na **p, *cp;

	නම් (name == NULL || environ == NULL)
		ආපසු (NULL);
	සඳහා (p = environ + *offset; (cp = *p) != NULL; ++p) {
		සඳහා (np = name, i = len; i && *cp; i--)
			නම් (*cp++ != *np++)
				bha_nga;
		නම් (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			ආපසු (cp);
		}
	}
	ආපසු (NULL);
}

#නම් 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
පූර්ණ_සංඛ්‍යා
putenv(var_na *str)
{
	var_na **P, *cp;
	size_t cnt;
	පූර්ණ_සංඛ්‍යා offset = 0;

	සඳහා (cp = str; *cp && *cp != '='; ++cp)
		;
	නම් (*cp != '=') {
		errno = EINVAL;
		ආපසු (-1);			/* missing `=' in string */
	}

	නම් (__findenv(str, (පූර්ණ_සංඛ්‍යා)(cp - str), &offset) != NULL) {
		environ[offset++] = str;
		/* could be set multiple times */
		අතරතුර (__findenv(str, (පූර්ණ_සංඛ්‍යා)(cp - str), &offset)) {
			සඳහා (P = &environ[offset];; ++P)
				නම් (!(*P = *(P + 1)))
					bha_nga;
		}
		ආපසු (0);
	}

	/* create new slot for string */
	සඳහා (P = environ; *P != NULL; P++)
		;
	cnt = P - environ;
	P = (var_na **)realloc(lastenv, parimaa_na(var_na *) * (cnt + 2));
	නම් (!P)
		ආපසු (-1);
	නම් (lastenv != environ)
		memcpy(P, environ, cnt * parimaa_na(var_na *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = NULL;
	ආපසු (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
පූර්ණ_සංඛ්‍යා
setenv(const var_na *name, const var_na *value, පූර්ණ_සංඛ්‍යා rewrite)
{
	var_na *C, **P;
	const var_na *np;
	පූර්ණ_සංඛ්‍යා l_value, offset = 0;

	සඳහා (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	නම් (*np) {
		errno = EINVAL;
		ආපසු (-1);			/* has `=' in name */
	}
#endif

	l_value = strlen(value);
	නම් ((C = __findenv(name, (පූර්ණ_සංඛ්‍යා)(np - name), &offset)) != NULL) {
		පූර්ණ_සංඛ්‍යා tmpoff = offset + 1;
		නම් (!rewrite)
			ආපසු (0);
#නම් 0 /* XXX - existing entry may not be writable */
		නම් (strlen(C) >= l_value) {	/* old larger; copy over */
			අතරතුර ((*C++ = *value++))
				;
			ආපසු (0);
		}
#endif
		/* could be set multiple times */
		අතරතුර (__findenv(name, (පූර්ණ_සංඛ්‍යා)(np - name), &tmpoff)) {
			සඳහා (P = &environ[tmpoff];; ++P)
				නම් (!(*P = *(P + 1)))
					bha_nga;
		}
	} නැතහොත් {					/* create new slot */
		size_t cnt;

		සඳහා (P = environ; *P != NULL; P++)
			;
		cnt = P - environ;
		P = (var_na **)realloc(lastenv, parimaa_na(var_na *) * (cnt + 2));
		නම් (!P)
			ආපසු (-1);
		නම් (lastenv != environ)
			memcpy(P, environ, cnt * parimaa_na(var_na *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = NULL;
	}
	නම් (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((පූර්ණ_සංඛ්‍යා)(np - name) + l_value + 2))))
		ආපසු (-1);
	සඳහා (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	සඳහා (*C++ = '='; (*C++ = *value++); )
		;
	ආපසු (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
පූර්ණ_සංඛ්‍යා
unsetenv(const var_na *name)
{
	var_na **P;
	const var_na *np;
	පූර්ණ_සංඛ්‍යා offset = 0;

	නම් (!name || !*name) {
		errno = EINVAL;
		ආපසු (-1);
	}
	සඳහා (np = name; *np && *np != '='; ++np)
		;
	නම් (*np) {
		errno = EINVAL;
		ආපසු (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	අතරතුර (__findenv(name, (පූර්ණ_සංඛ්‍යා)(np - name), &offset)) {
		සඳහා (P = &environ[offset];; ++P)
			නම් (!(*P = *(P + 1)))
				bha_nga;
	}
	ආපසු (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

