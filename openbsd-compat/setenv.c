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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

ਬਾਹਰੀ ਅੱਖਰ **environ;
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SETENV
ਸਥਿਰ ਅੱਖਰ **lastenv;				/* last value of environ */
#ਜੇ_ਅੰਤ

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
ਸਥਿਰ ਅੱਖਰ *
__findenv(ਅਚਲ ਅੱਖਰ *name, ਪੂਰਨ len, ਪੂਰਨ *ਵਿੱਥ)
{
	ਬਾਹਰੀ ਅੱਖਰ **environ;
	ਪੂਰਨ i;
	ਅਚਲ ਅੱਖਰ *np;
	ਅੱਖਰ **p, *cp;

	ਜੇ (name == ਨਿਰਾ || environ == ਨਿਰਾ)
		ਵਾਪਸ (ਨਿਰਾ);
	ਲਈ (p = environ + *ਵਿੱਥ; (cp = *p) != ਨਿਰਾ; ++p) {
		ਲਈ (np = name, i = len; i && *cp; i--)
			ਜੇ (*cp++ != *np++)
				ਰੋਕੋ;
		ਜੇ (i == 0 && *cp++ == '=') {
			*ਵਿੱਥ = p - environ;
			ਵਾਪਸ (cp);
		}
	}
	ਵਾਪਸ (ਨਿਰਾ);
}

#ਜੇ 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
ਪੂਰਨ
putenv(ਅੱਖਰ *str)
{
	ਅੱਖਰ **P, *cp;
	ਮਾਪ_t cnt;
	ਪੂਰਨ ਵਿੱਥ = 0;

	ਲਈ (cp = str; *cp && *cp != '='; ++cp)
		;
	ਜੇ (*cp != '=') {
		errno = EINVAL;
		ਵਾਪਸ (-1);			/* missing `=' in string */
	}

	ਜੇ (__findenv(str, (ਪੂਰਨ)(cp - str), &ਵਿੱਥ) != ਨਿਰਾ) {
		environ[ਵਿੱਥ++] = str;
		/* could be set multiple times */
		ਜਦੋਂ (__findenv(str, (ਪੂਰਨ)(cp - str), &ਵਿੱਥ)) {
			ਲਈ (P = &environ[ਵਿੱਥ];; ++P)
				ਜੇ (!(*P = *(P + 1)))
					ਰੋਕੋ;
		}
		ਵਾਪਸ (0);
	}

	/* create new slot for string */
	ਲਈ (P = environ; *P != ਨਿਰਾ; P++)
		;
	cnt = P - environ;
	P = (ਅੱਖਰ **)realloc(lastenv, ਆਕਾਰ(ਅੱਖਰ *) * (cnt + 2));
	ਜੇ (!P)
		ਵਾਪਸ (-1);
	ਜੇ (lastenv != environ)
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(P, environ, cnt * ਆਕਾਰ(ਅੱਖਰ *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = ਨਿਰਾ;
	ਵਾਪਸ (0);
}

#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
ਪੂਰਨ
setenv(ਅਚਲ ਅੱਖਰ *name, ਅਚਲ ਅੱਖਰ *ਮੁੱਲ, ਪੂਰਨ rewrite)
{
	ਅੱਖਰ *C, **P;
	ਅਚਲ ਅੱਖਰ *np;
	ਪੂਰਨ l_ਮੁੱਲ, ਵਿੱਥ = 0;

	ਲਈ (np = name; *np && *np != '='; ++np)
		;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ notyet
	ਜੇ (*np) {
		errno = EINVAL;
		ਵਾਪਸ (-1);			/* has `=' in name */
	}
#ਜੇ_ਅੰਤ

	l_ਮੁੱਲ = ਲੜੀ_ਲੰਬਾਈ(ਮੁੱਲ);
	ਜੇ ((C = __findenv(name, (ਪੂਰਨ)(np - name), &ਵਿੱਥ)) != ਨਿਰਾ) {
		ਪੂਰਨ tmpoff = ਵਿੱਥ + 1;
		ਜੇ (!rewrite)
			ਵਾਪਸ (0);
#ਜੇ 0 /* XXX - existing entry may not be writable */
		ਜੇ (ਲੜੀ_ਲੰਬਾਈ(C) >= l_ਮੁੱਲ) {	/* old larger; copy over */
			ਜਦੋਂ ((*C++ = *ਮੁੱਲ++))
				;
			ਵਾਪਸ (0);
		}
#ਜੇ_ਅੰਤ
		/* could be set multiple times */
		ਜਦੋਂ (__findenv(name, (ਪੂਰਨ)(np - name), &tmpoff)) {
			ਲਈ (P = &environ[tmpoff];; ++P)
				ਜੇ (!(*P = *(P + 1)))
					ਰੋਕੋ;
		}
	} ਨਹੀਂਤਾਂ {					/* create new slot */
		ਮਾਪ_t cnt;

		ਲਈ (P = environ; *P != ਨਿਰਾ; P++)
			;
		cnt = P - environ;
		P = (ਅੱਖਰ **)realloc(lastenv, ਆਕਾਰ(ਅੱਖਰ *) * (cnt + 2));
		ਜੇ (!P)
			ਵਾਪਸ (-1);
		ਜੇ (lastenv != environ)
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(P, environ, cnt * ਆਕਾਰ(ਅੱਖਰ *));
		lastenv = environ = P;
		ਵਿੱਥ = cnt;
		environ[cnt + 1] = ਨਿਰਾ;
	}
	ਜੇ (!(environ[ਵਿੱਥ] =			/* name + `=' + value */
	    ਸਮ੍ਰਿਤੀ_ਦਿਓ((ਮਾਪ_t)((ਪੂਰਨ)(np - name) + l_ਮੁੱਲ + 2))))
		ਵਾਪਸ (-1);
	ਲਈ (C = environ[ਵਿੱਥ]; (*C = *name++) && *C != '='; ++C)
		;
	ਲਈ (*C++ = '='; (*C++ = *ਮੁੱਲ++); )
		;
	ਵਾਪਸ (0);
}

#ਜੇ_ਅੰਤ /* HAVE_SETENV */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
ਪੂਰਨ
unsetenv(ਅਚਲ ਅੱਖਰ *name)
{
	ਅੱਖਰ **P;
	ਅਚਲ ਅੱਖਰ *np;
	ਪੂਰਨ ਵਿੱਥ = 0;

	ਜੇ (!name || !*name) {
		errno = EINVAL;
		ਵਾਪਸ (-1);
	}
	ਲਈ (np = name; *np && *np != '='; ++np)
		;
	ਜੇ (*np) {
		errno = EINVAL;
		ਵਾਪਸ (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	ਜਦੋਂ (__findenv(name, (ਪੂਰਨ)(np - name), &ਵਿੱਥ)) {
		ਲਈ (P = &environ[ਵਿੱਥ];; ++P)
			ਜੇ (!(*P = *(P + 1)))
				ਰੋਕੋ;
	}
	ਵਾਪਸ (0);
}
#ਜੇ_ਅੰਤ /* HAVE_UNSETENV */

#ਜੇ_ਅੰਤ /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

