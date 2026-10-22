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

#ಆದರೆ !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

ಬಾಹ್ಯ ಅಕ್ಷರ **environ;
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SETENV
ಸ್ಥಿರ ಅಕ್ಷರ **lastenv;				/* last value of environ */
#ಆದರೆ_ಅಂತ್ಯ

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
ಸ್ಥಿರ ಅಕ್ಷರ *
__findenv(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಪೂರ್ಣಾಂಕ len, ಪೂರ್ಣಾಂಕ *ಸ್ಥಾನಾಂತರ)
{
	ಬಾಹ್ಯ ಅಕ್ಷರ **environ;
	ಪೂರ್ಣಾಂಕ i;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *np;
	ಅಕ್ಷರ **p, *cp;

	ಆದರೆ (name == ಖಾಲಿ || environ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	ಗಾಗಿ (p = environ + *ಸ್ಥಾನಾಂತರ; (cp = *p) != ಖಾಲಿ; ++p) {
		ಗಾಗಿ (np = name, i = len; i && *cp; i--)
			ಆದರೆ (*cp++ != *np++)
				ನಿಲ್ಲಿಸು;
		ಆದರೆ (i == 0 && *cp++ == '=') {
			*ಸ್ಥಾನಾಂತರ = p - environ;
			ಹಿಂತಿರುಗಿ (cp);
		}
	}
	ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
}

#ಆದರೆ 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
ಪೂರ್ಣಾಂಕ
putenv(ಅಕ್ಷರ *str)
{
	ಅಕ್ಷರ **P, *cp;
	ಗಾತ್ರ_t cnt;
	ಪೂರ್ಣಾಂಕ ಸ್ಥಾನಾಂತರ = 0;

	ಗಾಗಿ (cp = str; *cp && *cp != '='; ++cp)
		;
	ಆದರೆ (*cp != '=') {
		errno = EINVAL;
		ಹಿಂತಿರುಗಿ (-1);			/* missing `=' in string */
	}

	ಆದರೆ (__findenv(str, (ಪೂರ್ಣಾಂಕ)(cp - str), &ಸ್ಥಾನಾಂತರ) != ಖಾಲಿ) {
		environ[ಸ್ಥಾನಾಂತರ++] = str;
		/* could be set multiple times */
		ಆಗ (__findenv(str, (ಪೂರ್ಣಾಂಕ)(cp - str), &ಸ್ಥಾನಾಂತರ)) {
			ಗಾಗಿ (P = &environ[ಸ್ಥಾನಾಂತರ];; ++P)
				ಆದರೆ (!(*P = *(P + 1)))
					ನಿಲ್ಲಿಸು;
		}
		ಹಿಂತಿರುಗಿ (0);
	}

	/* create new slot for string */
	ಗಾಗಿ (P = environ; *P != ಖಾಲಿ; P++)
		;
	cnt = P - environ;
	P = (ಅಕ್ಷರ **)realloc(lastenv, ಗಾತ್ರ(ಅಕ್ಷರ *) * (cnt + 2));
	ಆದರೆ (!P)
		ಹಿಂತಿರುಗಿ (-1);
	ಆದರೆ (lastenv != environ)
		ಸ್ಮರಣೆ_ನಕಲು(P, environ, cnt * ಗಾತ್ರ(ಅಕ್ಷರ *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ (0);
}

#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
ಪೂರ್ಣಾಂಕ
setenv(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮೌಲ್ಯ, ಪೂರ್ಣಾಂಕ rewrite)
{
	ಅಕ್ಷರ *C, **P;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *np;
	ಪೂರ್ಣಾಂಕ l_ಮೌಲ್ಯ, ಸ್ಥಾನಾಂತರ = 0;

	ಗಾಗಿ (np = name; *np && *np != '='; ++np)
		;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ notyet
	ಆದರೆ (*np) {
		errno = EINVAL;
		ಹಿಂತಿರುಗಿ (-1);			/* has `=' in name */
	}
#ಆದರೆ_ಅಂತ್ಯ

	l_ಮೌಲ್ಯ = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮೌಲ್ಯ);
	ಆದರೆ ((C = __findenv(name, (ಪೂರ್ಣಾಂಕ)(np - name), &ಸ್ಥಾನಾಂತರ)) != ಖಾಲಿ) {
		ಪೂರ್ಣಾಂಕ tmpoff = ಸ್ಥಾನಾಂತರ + 1;
		ಆದರೆ (!rewrite)
			ಹಿಂತಿರುಗಿ (0);
#ಆದರೆ 0 /* XXX - existing entry may not be writable */
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(C) >= l_ಮೌಲ್ಯ) {	/* old larger; copy over */
			ಆಗ ((*C++ = *ಮೌಲ್ಯ++))
				;
			ಹಿಂತಿರುಗಿ (0);
		}
#ಆದರೆ_ಅಂತ್ಯ
		/* could be set multiple times */
		ಆಗ (__findenv(name, (ಪೂರ್ಣಾಂಕ)(np - name), &tmpoff)) {
			ಗಾಗಿ (P = &environ[tmpoff];; ++P)
				ಆದರೆ (!(*P = *(P + 1)))
					ನಿಲ್ಲಿಸು;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {					/* create new slot */
		ಗಾತ್ರ_t cnt;

		ಗಾಗಿ (P = environ; *P != ಖಾಲಿ; P++)
			;
		cnt = P - environ;
		P = (ಅಕ್ಷರ **)realloc(lastenv, ಗಾತ್ರ(ಅಕ್ಷರ *) * (cnt + 2));
		ಆದರೆ (!P)
			ಹಿಂತಿರುಗಿ (-1);
		ಆದರೆ (lastenv != environ)
			ಸ್ಮರಣೆ_ನಕಲು(P, environ, cnt * ಗಾತ್ರ(ಅಕ್ಷರ *));
		lastenv = environ = P;
		ಸ್ಥಾನಾಂತರ = cnt;
		environ[cnt + 1] = ಖಾಲಿ;
	}
	ಆದರೆ (!(environ[ಸ್ಥಾನಾಂತರ] =			/* name + `=' + value */
	    ಸ್ಮರಣೆ_ಕೊಡು((ಗಾತ್ರ_t)((ಪೂರ್ಣಾಂಕ)(np - name) + l_ಮೌಲ್ಯ + 2))))
		ಹಿಂತಿರುಗಿ (-1);
	ಗಾಗಿ (C = environ[ಸ್ಥಾನಾಂತರ]; (*C = *name++) && *C != '='; ++C)
		;
	ಗಾಗಿ (*C++ = '='; (*C++ = *ಮೌಲ್ಯ++); )
		;
	ಹಿಂತಿರುಗಿ (0);
}

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_SETENV */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
ಪೂರ್ಣಾಂಕ
unsetenv(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಅಕ್ಷರ **P;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *np;
	ಪೂರ್ಣಾಂಕ ಸ್ಥಾನಾಂತರ = 0;

	ಆದರೆ (!name || !*name) {
		errno = EINVAL;
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಗಾಗಿ (np = name; *np && *np != '='; ++np)
		;
	ಆದರೆ (*np) {
		errno = EINVAL;
		ಹಿಂತಿರುಗಿ (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	ಆಗ (__findenv(name, (ಪೂರ್ಣಾಂಕ)(np - name), &ಸ್ಥಾನಾಂತರ)) {
		ಗಾಗಿ (P = &environ[ಸ್ಥಾನಾಂತರ];; ++P)
			ಆದರೆ (!(*P = *(P + 1)))
				ನಿಲ್ಲಿಸು;
	}
	ಹಿಂತಿರುಗಿ (0);
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_UNSETENV */

#ಆದರೆ_ಅಂತ್ಯ /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

