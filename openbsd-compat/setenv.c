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

#அந்தர்பாவ "includes.h"

#எனில் !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

வெளி எழுத்து **environ;
#ifndef HAVE_SETENV
நிலையான எழுத்து **lastenv;				/* last value of environ */
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
நிலையான எழுத்து *
__findenv(மாறிலி எழுத்து *name, முழு len, முழு *offset)
{
	வெளி எழுத்து **environ;
	முழு i;
	மாறிலி எழுத்து *np;
	எழுத்து **p, *cp;

	எனில் (name == வெற்று || environ == வெற்று)
		திரும்பு (வெற்று);
	க்கு (p = environ + *offset; (cp = *p) != வெற்று; ++p) {
		க்கு (np = name, i = len; i && *cp; i--)
			எனில் (*cp++ != *np++)
				நிறுத்து;
		எனில் (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			திரும்பு (cp);
		}
	}
	திரும்பு (வெற்று);
}

#எனில் 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
முழு
putenv(எழுத்து *str)
{
	எழுத்து **P, *cp;
	size_t cnt;
	முழு offset = 0;

	க்கு (cp = str; *cp && *cp != '='; ++cp)
		;
	எனில் (*cp != '=') {
		errno = EINVAL;
		திரும்பு (-1);			/* missing `=' in string */
	}

	எனில் (__findenv(str, (முழு)(cp - str), &offset) != வெற்று) {
		environ[offset++] = str;
		/* could be set multiple times */
		போது (__findenv(str, (முழு)(cp - str), &offset)) {
			க்கு (P = &environ[offset];; ++P)
				எனில் (!(*P = *(P + 1)))
					நிறுத்து;
		}
		திரும்பு (0);
	}

	/* create new slot for string */
	க்கு (P = environ; *P != வெற்று; P++)
		;
	cnt = P - environ;
	P = (எழுத்து **)realloc(lastenv, அளவு(எழுத்து *) * (cnt + 2));
	எனில் (!P)
		திரும்பு (-1);
	எனில் (lastenv != environ)
		memcpy(P, environ, cnt * அளவு(எழுத்து *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = வெற்று;
	திரும்பு (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
முழு
setenv(மாறிலி எழுத்து *name, மாறிலி எழுத்து *மதிப்பு, முழு rewrite)
{
	எழுத்து *C, **P;
	மாறிலி எழுத்து *np;
	முழு l_மதிப்பு, offset = 0;

	க்கு (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	எனில் (*np) {
		errno = EINVAL;
		திரும்பு (-1);			/* has `=' in name */
	}
#endif

	l_மதிப்பு = strlen(மதிப்பு);
	எனில் ((C = __findenv(name, (முழு)(np - name), &offset)) != வெற்று) {
		முழு tmpoff = offset + 1;
		எனில் (!rewrite)
			திரும்பு (0);
#எனில் 0 /* XXX - existing entry may not be writable */
		எனில் (strlen(C) >= l_மதிப்பு) {	/* old larger; copy over */
			போது ((*C++ = *மதிப்பு++))
				;
			திரும்பு (0);
		}
#endif
		/* could be set multiple times */
		போது (__findenv(name, (முழு)(np - name), &tmpoff)) {
			க்கு (P = &environ[tmpoff];; ++P)
				எனில் (!(*P = *(P + 1)))
					நிறுத்து;
		}
	} இல்லையெனில் {					/* create new slot */
		size_t cnt;

		க்கு (P = environ; *P != வெற்று; P++)
			;
		cnt = P - environ;
		P = (எழுத்து **)realloc(lastenv, அளவு(எழுத்து *) * (cnt + 2));
		எனில் (!P)
			திரும்பு (-1);
		எனில் (lastenv != environ)
			memcpy(P, environ, cnt * அளவு(எழுத்து *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = வெற்று;
	}
	எனில் (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((முழு)(np - name) + l_மதிப்பு + 2))))
		திரும்பு (-1);
	க்கு (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	க்கு (*C++ = '='; (*C++ = *மதிப்பு++); )
		;
	திரும்பு (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
முழு
unsetenv(மாறிலி எழுத்து *name)
{
	எழுத்து **P;
	மாறிலி எழுத்து *np;
	முழு offset = 0;

	எனில் (!name || !*name) {
		errno = EINVAL;
		திரும்பு (-1);
	}
	க்கு (np = name; *np && *np != '='; ++np)
		;
	எனில் (*np) {
		errno = EINVAL;
		திரும்பு (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	போது (__findenv(name, (முழு)(np - name), &offset)) {
		க்கு (P = &environ[offset];; ++P)
			எனில் (!(*P = *(P + 1)))
				நிறுத்து;
	}
	திரும்பு (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

