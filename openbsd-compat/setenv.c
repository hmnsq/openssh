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

#אם !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

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

	אם (name == عدم || environ == عدم)
		החזר (عدم);
	עבור (p = environ + *offset; (cp = *p) != عدم; ++p) {
		עבור (np = name, i = len; i && *cp; i--)
			אם (*cp++ != *np++)
				اكسر;
		אם (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			החזר (cp);
		}
	}
	החזר (عدم);
}

#אם 0 /* nothing uses putenv */
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

	עבור (cp = str; *cp && *cp != '='; ++cp)
		;
	אם (*cp != '=') {
		errno = EINVAL;
		החזר (-1);			/* missing `=' in string */
	}

	אם (__findenv(str, (صحيح)(cp - str), &offset) != عدم) {
		environ[offset++] = str;
		/* could be set multiple times */
		כלעוד (__findenv(str, (صحيح)(cp - str), &offset)) {
			עבור (P = &environ[offset];; ++P)
				אם (!(*P = *(P + 1)))
					اكسر;
		}
		החזר (0);
	}

	/* create new slot for string */
	עבור (P = environ; *P != عدم; P++)
		;
	cnt = P - environ;
	P = (حرف **)realloc(lastenv, حجم(حرف *) * (cnt + 2));
	אם (!P)
		החזר (-1);
	אם (lastenv != environ)
		memcpy(P, environ, cnt * حجم(حرف *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = عدم;
	החזר (0);
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

	עבור (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	אם (*np) {
		errno = EINVAL;
		החזר (-1);			/* has `=' in name */
	}
#endif

	l_value = strlen(value);
	אם ((C = __findenv(name, (صحيح)(np - name), &offset)) != عدم) {
		صحيح tmpoff = offset + 1;
		אם (!rewrite)
			החזר (0);
#אם 0 /* XXX - existing entry may not be writable */
		אם (strlen(C) >= l_value) {	/* old larger; copy over */
			כלעוד ((*C++ = *value++))
				;
			החזר (0);
		}
#endif
		/* could be set multiple times */
		כלעוד (__findenv(name, (صحيح)(np - name), &tmpoff)) {
			עבור (P = &environ[tmpoff];; ++P)
				אם (!(*P = *(P + 1)))
					اكسر;
		}
	} אחרת {					/* create new slot */
		size_t cnt;

		עבור (P = environ; *P != عدم; P++)
			;
		cnt = P - environ;
		P = (حرف **)realloc(lastenv, حجم(حرف *) * (cnt + 2));
		אם (!P)
			החזר (-1);
		אם (lastenv != environ)
			memcpy(P, environ, cnt * حجم(حرف *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = عدم;
	}
	אם (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((صحيح)(np - name) + l_value + 2))))
		החזר (-1);
	עבור (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	עבור (*C++ = '='; (*C++ = *value++); )
		;
	החזר (0);
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

	אם (!name || !*name) {
		errno = EINVAL;
		החזר (-1);
	}
	עבור (np = name; *np && *np != '='; ++np)
		;
	אם (*np) {
		errno = EINVAL;
		החזר (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	כלעוד (__findenv(name, (صحيح)(np - name), &offset)) {
		עבור (P = &environ[offset];; ++P)
			אם (!(*P = *(P + 1)))
				اكسر;
	}
	החזר (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

