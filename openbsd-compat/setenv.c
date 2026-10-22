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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಯದಿ !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

ಬಾಹ್ಯ ವರ್ಣ **environ;
#ifndef HAVE_SETENV
ಸ್ಥಿರ ವರ್ಣ **lastenv;				/* last value of environ */
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
ಸ್ಥಿರ ವರ್ಣ *
__findenv(ಧ್ರುವ ವರ್ಣ *name, ಪೂರ್ಣಾಙ್ಕ len, ಪೂರ್ಣಾಙ್ಕ *offset)
{
	ಬಾಹ್ಯ ವರ್ಣ **environ;
	ಪೂರ್ಣಾಙ್ಕ i;
	ಧ್ರುವ ವರ್ಣ *np;
	ವರ್ಣ **p, *cp;

	ಯದಿ (name == ರಿಕ್ತ || environ == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	ಪ್ರತಿ (p = environ + *offset; (cp = *p) != ರಿಕ್ತ; ++p) {
		ಪ್ರತಿ (np = name, i = len; i && *cp; i--)
			ಯದಿ (*cp++ != *np++)
				ಭಙ್ಗ;
		ಯದಿ (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			ಪ್ರತ್ಯಾಗಮ (cp);
		}
	}
	ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
}

#ಯದಿ 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
ಪೂರ್ಣಾಙ್ಕ
putenv(ವರ್ಣ *str)
{
	ವರ್ಣ **P, *cp;
	size_t cnt;
	ಪೂರ್ಣಾಙ್ಕ offset = 0;

	ಪ್ರತಿ (cp = str; *cp && *cp != '='; ++cp)
		;
	ಯದಿ (*cp != '=') {
		errno = EINVAL;
		ಪ್ರತ್ಯಾಗಮ (-1);			/* missing `=' in string */
	}

	ಯದಿ (__findenv(str, (ಪೂರ್ಣಾಙ್ಕ)(cp - str), &offset) != ರಿಕ್ತ) {
		environ[offset++] = str;
		/* could be set multiple times */
		ಯಾವತ್ (__findenv(str, (ಪೂರ್ಣಾಙ್ಕ)(cp - str), &offset)) {
			ಪ್ರತಿ (P = &environ[offset];; ++P)
				ಯದಿ (!(*P = *(P + 1)))
					ಭಙ್ಗ;
		}
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	/* create new slot for string */
	ಪ್ರತಿ (P = environ; *P != ರಿಕ್ತ; P++)
		;
	cnt = P - environ;
	P = (ವರ್ಣ **)realloc(lastenv, ಪರಿಮಾಣ(ವರ್ಣ *) * (cnt + 2));
	ಯದಿ (!P)
		ಪ್ರತ್ಯಾಗಮ (-1);
	ಯದಿ (lastenv != environ)
		memcpy(P, environ, cnt * ಪರಿಮಾಣ(ವರ್ಣ *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
ಪೂರ್ಣಾಙ್ಕ
setenv(ಧ್ರುವ ವರ್ಣ *name, ಧ್ರುವ ವರ್ಣ *ಮೌಲ್ಯ, ಪೂರ್ಣಾಙ್ಕ rewrite)
{
	ವರ್ಣ *C, **P;
	ಧ್ರುವ ವರ್ಣ *np;
	ಪೂರ್ಣಾಙ್ಕ l_ಮೌಲ್ಯ, offset = 0;

	ಪ್ರತಿ (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	ಯದಿ (*np) {
		errno = EINVAL;
		ಪ್ರತ್ಯಾಗಮ (-1);			/* has `=' in name */
	}
#endif

	l_ಮೌಲ್ಯ = strlen(ಮೌಲ್ಯ);
	ಯದಿ ((C = __findenv(name, (ಪೂರ್ಣಾಙ್ಕ)(np - name), &offset)) != ರಿಕ್ತ) {
		ಪೂರ್ಣಾಙ್ಕ tmpoff = offset + 1;
		ಯದಿ (!rewrite)
			ಪ್ರತ್ಯಾಗಮ (0);
#ಯದಿ 0 /* XXX - existing entry may not be writable */
		ಯದಿ (strlen(C) >= l_ಮೌಲ್ಯ) {	/* old larger; copy over */
			ಯಾವತ್ ((*C++ = *ಮೌಲ್ಯ++))
				;
			ಪ್ರತ್ಯಾಗಮ (0);
		}
#endif
		/* could be set multiple times */
		ಯಾವತ್ (__findenv(name, (ಪೂರ್ಣಾಙ್ಕ)(np - name), &tmpoff)) {
			ಪ್ರತಿ (P = &environ[tmpoff];; ++P)
				ಯದಿ (!(*P = *(P + 1)))
					ಭಙ್ಗ;
		}
	} ಅನ್ಯಥಾ {					/* create new slot */
		size_t cnt;

		ಪ್ರತಿ (P = environ; *P != ರಿಕ್ತ; P++)
			;
		cnt = P - environ;
		P = (ವರ್ಣ **)realloc(lastenv, ಪರಿಮಾಣ(ವರ್ಣ *) * (cnt + 2));
		ಯದಿ (!P)
			ಪ್ರತ್ಯಾಗಮ (-1);
		ಯದಿ (lastenv != environ)
			memcpy(P, environ, cnt * ಪರಿಮಾಣ(ವರ್ಣ *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = ರಿಕ್ತ;
	}
	ಯದಿ (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((ಪೂರ್ಣಾಙ್ಕ)(np - name) + l_ಮೌಲ್ಯ + 2))))
		ಪ್ರತ್ಯಾಗಮ (-1);
	ಪ್ರತಿ (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	ಪ್ರತಿ (*C++ = '='; (*C++ = *ಮೌಲ್ಯ++); )
		;
	ಪ್ರತ್ಯಾಗಮ (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
ಪೂರ್ಣಾಙ್ಕ
unsetenv(ಧ್ರುವ ವರ್ಣ *name)
{
	ವರ್ಣ **P;
	ಧ್ರುವ ವರ್ಣ *np;
	ಪೂರ್ಣಾಙ್ಕ offset = 0;

	ಯದಿ (!name || !*name) {
		errno = EINVAL;
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಪ್ರತಿ (np = name; *np && *np != '='; ++np)
		;
	ಯದಿ (*np) {
		errno = EINVAL;
		ಪ್ರತ್ಯಾಗಮ (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	ಯಾವತ್ (__findenv(name, (ಪೂರ್ಣಾಙ್ಕ)(np - name), &offset)) {
		ಪ್ರತಿ (P = &environ[offset];; ++P)
			ಯದಿ (!(*P = *(P + 1)))
				ಭಙ್ಗ;
	}
	ಪ್ರತ್ಯಾಗಮ (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

