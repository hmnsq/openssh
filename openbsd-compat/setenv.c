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

#شامل "includes.h"

#اگر !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#شامل <errno.h>
#شامل <stdlib.h>
#شامل <string.h>

بیرونی نویسه **environ;
#ifndef HAVE_SETENV
ایستا نویسه **lastenv;				/* last value of environ */
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
ایستا نویسه *
__findenv(ثابت نویسه *name, صحیح len, صحیح *offset)
{
	بیرونی نویسه **environ;
	صحیح i;
	ثابت نویسه *np;
	نویسه **p, *cp;

	اگر (name == پوچ || environ == پوچ)
		بازگشت (پوچ);
	برای (p = environ + *offset; (cp = *p) != پوچ; ++p) {
		برای (np = name, i = len; i && *cp; i--)
			اگر (*cp++ != *np++)
				بشکن;
		اگر (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			بازگشت (cp);
		}
	}
	بازگشت (پوچ);
}

#اگر 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
صحیح
putenv(نویسه *str)
{
	نویسه **P, *cp;
	size_t cnt;
	صحیح offset = 0;

	برای (cp = str; *cp && *cp != '='; ++cp)
		;
	اگر (*cp != '=') {
		errno = EINVAL;
		بازگشت (-1);			/* missing `=' in string */
	}

	اگر (__findenv(str, (صحیح)(cp - str), &offset) != پوچ) {
		environ[offset++] = str;
		/* could be set multiple times */
		وقتی (__findenv(str, (صحیح)(cp - str), &offset)) {
			برای (P = &environ[offset];; ++P)
				اگر (!(*P = *(P + 1)))
					بشکن;
		}
		بازگشت (0);
	}

	/* create new slot for string */
	برای (P = environ; *P != پوچ; P++)
		;
	cnt = P - environ;
	P = (نویسه **)realloc(lastenv, اندازه(نویسه *) * (cnt + 2));
	اگر (!P)
		بازگشت (-1);
	اگر (lastenv != environ)
		memcpy(P, environ, cnt * اندازه(نویسه *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = پوچ;
	بازگشت (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
صحیح
setenv(ثابت نویسه *name, ثابت نویسه *مقدار, صحیح rewrite)
{
	نویسه *C, **P;
	ثابت نویسه *np;
	صحیح l_مقدار, offset = 0;

	برای (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	اگر (*np) {
		errno = EINVAL;
		بازگشت (-1);			/* has `=' in name */
	}
#endif

	l_مقدار = strlen(مقدار);
	اگر ((C = __findenv(name, (صحیح)(np - name), &offset)) != پوچ) {
		صحیح tmpoff = offset + 1;
		اگر (!rewrite)
			بازگشت (0);
#اگر 0 /* XXX - existing entry may not be writable */
		اگر (strlen(C) >= l_مقدار) {	/* old larger; copy over */
			وقتی ((*C++ = *مقدار++))
				;
			بازگشت (0);
		}
#endif
		/* could be set multiple times */
		وقتی (__findenv(name, (صحیح)(np - name), &tmpoff)) {
			برای (P = &environ[tmpoff];; ++P)
				اگر (!(*P = *(P + 1)))
					بشکن;
		}
	} وگرنه {					/* create new slot */
		size_t cnt;

		برای (P = environ; *P != پوچ; P++)
			;
		cnt = P - environ;
		P = (نویسه **)realloc(lastenv, اندازه(نویسه *) * (cnt + 2));
		اگر (!P)
			بازگشت (-1);
		اگر (lastenv != environ)
			memcpy(P, environ, cnt * اندازه(نویسه *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = پوچ;
	}
	اگر (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((صحیح)(np - name) + l_مقدار + 2))))
		بازگشت (-1);
	برای (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	برای (*C++ = '='; (*C++ = *مقدار++); )
		;
	بازگشت (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
صحیح
unsetenv(ثابت نویسه *name)
{
	نویسه **P;
	ثابت نویسه *np;
	صحیح offset = 0;

	اگر (!name || !*name) {
		errno = EINVAL;
		بازگشت (-1);
	}
	برای (np = name; *np && *np != '='; ++np)
		;
	اگر (*np) {
		errno = EINVAL;
		بازگشت (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	وقتی (__findenv(name, (صحیح)(np - name), &offset)) {
		برای (P = &environ[offset];; ++P)
			اگر (!(*P = *(P + 1)))
				بشکن;
	}
	بازگشت (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

