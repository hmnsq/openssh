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

#ضمن "includes.h"

#𐡄𐡍 !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#ضمن <errno.h>
#ضمن <stdlib.h>
#ضمن <string.h>

خارجي حرف **environ;
#ifndef HAVE_SETENV
ساكن حرف **lastenv;				/* last value of environ */
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
ساكن حرف *
__findenv(ثابت حرف *name, صحيح len, صحيح *offset)
{
	خارجي حرف **environ;
	صحيح i;
	ثابت حرف *np;
	حرف **p, *cp;

	𐡄𐡍 (name == عدم || environ == عدم)
		أرجع (عدم);
	لكل (p = environ + *offset; (cp = *p) != عدم; ++p) {
		لكل (np = name, i = len; i && *cp; i--)
			𐡄𐡍 (*cp++ != *np++)
				اكسر;
		𐡄𐡍 (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			أرجع (cp);
		}
	}
	أرجع (عدم);
}

#𐡄𐡍 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
صحيح
putenv(حرف *str)
{
	حرف **P, *cp;
	size_t cnt;
	صحيح offset = 0;

	لكل (cp = str; *cp && *cp != '='; ++cp)
		;
	𐡄𐡍 (*cp != '=') {
		errno = EINVAL;
		أرجع (-1);			/* missing `=' in string */
	}

	𐡄𐡍 (__findenv(str, (صحيح)(cp - str), &offset) != عدم) {
		environ[offset++] = str;
		/* could be set multiple times */
		طالما (__findenv(str, (صحيح)(cp - str), &offset)) {
			لكل (P = &environ[offset];; ++P)
				𐡄𐡍 (!(*P = *(P + 1)))
					اكسر;
		}
		أرجع (0);
	}

	/* create new slot for string */
	لكل (P = environ; *P != عدم; P++)
		;
	cnt = P - environ;
	P = (حرف **)realloc(lastenv, حجم(حرف *) * (cnt + 2));
	𐡄𐡍 (!P)
		أرجع (-1);
	𐡄𐡍 (lastenv != environ)
		memcpy(P, environ, cnt * حجم(حرف *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = عدم;
	أرجع (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
صحيح
setenv(ثابت حرف *name, ثابت حرف *value, صحيح rewrite)
{
	حرف *C, **P;
	ثابت حرف *np;
	صحيح l_value, offset = 0;

	لكل (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	𐡄𐡍 (*np) {
		errno = EINVAL;
		أرجع (-1);			/* has `=' in name */
	}
#endif

	l_value = strlen(value);
	𐡄𐡍 ((C = __findenv(name, (صحيح)(np - name), &offset)) != عدم) {
		صحيح tmpoff = offset + 1;
		𐡄𐡍 (!rewrite)
			أرجع (0);
#𐡄𐡍 0 /* XXX - existing entry may not be writable */
		𐡄𐡍 (strlen(C) >= l_value) {	/* old larger; copy over */
			طالما ((*C++ = *value++))
				;
			أرجع (0);
		}
#endif
		/* could be set multiple times */
		طالما (__findenv(name, (صحيح)(np - name), &tmpoff)) {
			لكل (P = &environ[tmpoff];; ++P)
				𐡄𐡍 (!(*P = *(P + 1)))
					اكسر;
		}
	} وإلا {					/* create new slot */
		size_t cnt;

		لكل (P = environ; *P != عدم; P++)
			;
		cnt = P - environ;
		P = (حرف **)realloc(lastenv, حجم(حرف *) * (cnt + 2));
		𐡄𐡍 (!P)
			أرجع (-1);
		𐡄𐡍 (lastenv != environ)
			memcpy(P, environ, cnt * حجم(حرف *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = عدم;
	}
	𐡄𐡍 (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((صحيح)(np - name) + l_value + 2))))
		أرجع (-1);
	لكل (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	لكل (*C++ = '='; (*C++ = *value++); )
		;
	أرجع (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
صحيح
unsetenv(ثابت حرف *name)
{
	حرف **P;
	ثابت حرف *np;
	صحيح offset = 0;

	𐡄𐡍 (!name || !*name) {
		errno = EINVAL;
		أرجع (-1);
	}
	لكل (np = name; *np && *np != '='; ++np)
		;
	𐡄𐡍 (*np) {
		errno = EINVAL;
		أرجع (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	طالما (__findenv(name, (صحيح)(np - name), &offset)) {
		لكل (P = &environ[offset];; ++P)
			𐡄𐡍 (!(*P = *(P + 1)))
				اكسر;
	}
	أرجع (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

