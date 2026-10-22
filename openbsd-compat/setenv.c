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

#અન્તર્ભાવ "includes.h"

#જો !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

બાહ્ય અક્ષર **environ;
#ifndef HAVE_SETENV
સ્થિર અક્ષર **lastenv;				/* last value of environ */
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
સ્થિર અક્ષર *
__findenv(અચલ અક્ષર *name, પૂર્ણાંક len, પૂર્ણાંક *offset)
{
	બાહ્ય અક્ષર **environ;
	પૂર્ણાંક i;
	અચલ અક્ષર *np;
	અક્ષર **p, *cp;

	જો (name == ખાલી || environ == ખાલી)
		પાછા (ખાલી);
	માટે (p = environ + *offset; (cp = *p) != ખાલી; ++p) {
		માટે (np = name, i = len; i && *cp; i--)
			જો (*cp++ != *np++)
				તોડો;
		જો (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			પાછા (cp);
		}
	}
	પાછા (ખાલી);
}

#જો 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
પૂર્ણાંક
putenv(અક્ષર *str)
{
	અક્ષર **P, *cp;
	size_t cnt;
	પૂર્ણાંક offset = 0;

	માટે (cp = str; *cp && *cp != '='; ++cp)
		;
	જો (*cp != '=') {
		errno = EINVAL;
		પાછા (-1);			/* missing `=' in string */
	}

	જો (__findenv(str, (પૂર્ણાંક)(cp - str), &offset) != ખાલી) {
		environ[offset++] = str;
		/* could be set multiple times */
		જ્યારે (__findenv(str, (પૂર્ણાંક)(cp - str), &offset)) {
			માટે (P = &environ[offset];; ++P)
				જો (!(*P = *(P + 1)))
					તોડો;
		}
		પાછા (0);
	}

	/* create new slot for string */
	માટે (P = environ; *P != ખાલી; P++)
		;
	cnt = P - environ;
	P = (અક્ષર **)realloc(lastenv, કદ(અક્ષર *) * (cnt + 2));
	જો (!P)
		પાછા (-1);
	જો (lastenv != environ)
		memcpy(P, environ, cnt * કદ(અક્ષર *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = ખાલી;
	પાછા (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
પૂર્ણાંક
setenv(અચલ અક્ષર *name, અચલ અક્ષર *કિંમત, પૂર્ણાંક rewrite)
{
	અક્ષર *C, **P;
	અચલ અક્ષર *np;
	પૂર્ણાંક l_કિંમત, offset = 0;

	માટે (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	જો (*np) {
		errno = EINVAL;
		પાછા (-1);			/* has `=' in name */
	}
#endif

	l_કિંમત = strlen(કિંમત);
	જો ((C = __findenv(name, (પૂર્ણાંક)(np - name), &offset)) != ખાલી) {
		પૂર્ણાંક tmpoff = offset + 1;
		જો (!rewrite)
			પાછા (0);
#જો 0 /* XXX - existing entry may not be writable */
		જો (strlen(C) >= l_કિંમત) {	/* old larger; copy over */
			જ્યારે ((*C++ = *કિંમત++))
				;
			પાછા (0);
		}
#endif
		/* could be set multiple times */
		જ્યારે (__findenv(name, (પૂર્ણાંક)(np - name), &tmpoff)) {
			માટે (P = &environ[tmpoff];; ++P)
				જો (!(*P = *(P + 1)))
					તોડો;
		}
	} નહીંતર {					/* create new slot */
		size_t cnt;

		માટે (P = environ; *P != ખાલી; P++)
			;
		cnt = P - environ;
		P = (અક્ષર **)realloc(lastenv, કદ(અક્ષર *) * (cnt + 2));
		જો (!P)
			પાછા (-1);
		જો (lastenv != environ)
			memcpy(P, environ, cnt * કદ(અક્ષર *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = ખાલી;
	}
	જો (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((પૂર્ણાંક)(np - name) + l_કિંમત + 2))))
		પાછા (-1);
	માટે (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	માટે (*C++ = '='; (*C++ = *કિંમત++); )
		;
	પાછા (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
પૂર્ણાંક
unsetenv(અચલ અક્ષર *name)
{
	અક્ષર **P;
	અચલ અક્ષર *np;
	પૂર્ણાંક offset = 0;

	જો (!name || !*name) {
		errno = EINVAL;
		પાછા (-1);
	}
	માટે (np = name; *np && *np != '='; ++np)
		;
	જો (*np) {
		errno = EINVAL;
		પાછા (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	જ્યારે (__findenv(name, (પૂર્ણાંક)(np - name), &offset)) {
		માટે (P = &environ[offset];; ++P)
			જો (!(*P = *(P + 1)))
				તોડો;
	}
	પાછા (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

