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

#ຖ້າ !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

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
__findenv(const var_na *name, ຈຳນວນເຕັມ len, ຈຳນວນເຕັມ *offset)
{
	extern var_na **environ;
	ຈຳນວນເຕັມ i;
	const var_na *np;
	var_na **p, *cp;

	ຖ້າ (name == NULL || environ == NULL)
		ສົ່ງຄືນ (NULL);
	ສຳລັບ (p = environ + *offset; (cp = *p) != NULL; ++p) {
		ສຳລັບ (np = name, i = len; i && *cp; i--)
			ຖ້າ (*cp++ != *np++)
				bha_nga;
		ຖ້າ (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			ສົ່ງຄືນ (cp);
		}
	}
	ສົ່ງຄືນ (NULL);
}

#ຖ້າ 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
ຈຳນວນເຕັມ
putenv(var_na *str)
{
	var_na **P, *cp;
	size_t cnt;
	ຈຳນວນເຕັມ offset = 0;

	ສຳລັບ (cp = str; *cp && *cp != '='; ++cp)
		;
	ຖ້າ (*cp != '=') {
		errno = EINVAL;
		ສົ່ງຄືນ (-1);			/* missing `=' in string */
	}

	ຖ້າ (__findenv(str, (ຈຳນວນເຕັມ)(cp - str), &offset) != NULL) {
		environ[offset++] = str;
		/* could be set multiple times */
		ໃນຂະນະທີ່ (__findenv(str, (ຈຳນວນເຕັມ)(cp - str), &offset)) {
			ສຳລັບ (P = &environ[offset];; ++P)
				ຖ້າ (!(*P = *(P + 1)))
					bha_nga;
		}
		ສົ່ງຄືນ (0);
	}

	/* create new slot for string */
	ສຳລັບ (P = environ; *P != NULL; P++)
		;
	cnt = P - environ;
	P = (var_na **)realloc(lastenv, parimaa_na(var_na *) * (cnt + 2));
	ຖ້າ (!P)
		ສົ່ງຄືນ (-1);
	ຖ້າ (lastenv != environ)
		memcpy(P, environ, cnt * parimaa_na(var_na *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = NULL;
	ສົ່ງຄືນ (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
ຈຳນວນເຕັມ
setenv(const var_na *name, const var_na *value, ຈຳນວນເຕັມ rewrite)
{
	var_na *C, **P;
	const var_na *np;
	ຈຳນວນເຕັມ l_value, offset = 0;

	ສຳລັບ (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	ຖ້າ (*np) {
		errno = EINVAL;
		ສົ່ງຄືນ (-1);			/* has `=' in name */
	}
#endif

	l_value = strlen(value);
	ຖ້າ ((C = __findenv(name, (ຈຳນວນເຕັມ)(np - name), &offset)) != NULL) {
		ຈຳນວນເຕັມ tmpoff = offset + 1;
		ຖ້າ (!rewrite)
			ສົ່ງຄືນ (0);
#ຖ້າ 0 /* XXX - existing entry may not be writable */
		ຖ້າ (strlen(C) >= l_value) {	/* old larger; copy over */
			ໃນຂະນະທີ່ ((*C++ = *value++))
				;
			ສົ່ງຄືນ (0);
		}
#endif
		/* could be set multiple times */
		ໃນຂະນະທີ່ (__findenv(name, (ຈຳນວນເຕັມ)(np - name), &tmpoff)) {
			ສຳລັບ (P = &environ[tmpoff];; ++P)
				ຖ້າ (!(*P = *(P + 1)))
					bha_nga;
		}
	} ບໍ່ດັ່ງນັ້ນ {					/* create new slot */
		size_t cnt;

		ສຳລັບ (P = environ; *P != NULL; P++)
			;
		cnt = P - environ;
		P = (var_na **)realloc(lastenv, parimaa_na(var_na *) * (cnt + 2));
		ຖ້າ (!P)
			ສົ່ງຄືນ (-1);
		ຖ້າ (lastenv != environ)
			memcpy(P, environ, cnt * parimaa_na(var_na *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = NULL;
	}
	ຖ້າ (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((ຈຳນວນເຕັມ)(np - name) + l_value + 2))))
		ສົ່ງຄືນ (-1);
	ສຳລັບ (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	ສຳລັບ (*C++ = '='; (*C++ = *value++); )
		;
	ສົ່ງຄືນ (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
ຈຳນວນເຕັມ
unsetenv(const var_na *name)
{
	var_na **P;
	const var_na *np;
	ຈຳນວນເຕັມ offset = 0;

	ຖ້າ (!name || !*name) {
		errno = EINVAL;
		ສົ່ງຄືນ (-1);
	}
	ສຳລັບ (np = name; *np && *np != '='; ++np)
		;
	ຖ້າ (*np) {
		errno = EINVAL;
		ສົ່ງຄືນ (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	ໃນຂະນະທີ່ (__findenv(name, (ຈຳນວນເຕັມ)(np - name), &offset)) {
		ສຳລັບ (P = &environ[offset];; ++P)
			ຖ້າ (!(*P = *(P + 1)))
				bha_nga;
	}
	ສົ່ງຄືນ (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

