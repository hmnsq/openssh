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

خارجی حرف **environ;
#اگر_غیر_تعریف_شدہ HAVE_SETENV
ساکن حرف **lastenv;				/* last value of environ */
#اگر_ختم

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
ساکن حرف *
__findenv(ثابت حرف *name, صحیح len, صحیح *انحراف)
{
	خارجی حرف **environ;
	صحیح i;
	ثابت حرف *np;
	حرف **p, *cp;

	اگر (name == تہی || environ == تہی)
		واپس (تہی);
	برائے (p = environ + *انحراف; (cp = *p) != تہی; ++p) {
		برائے (np = name, i = len; i && *cp; i--)
			اگر (*cp++ != *np++)
				توڑو;
		اگر (i == 0 && *cp++ == '=') {
			*انحراف = p - environ;
			واپس (cp);
		}
	}
	واپس (تہی);
}

#اگر 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
صحیح
putenv(حرف *str)
{
	حرف **P, *cp;
	سائز_t cnt;
	صحیح انحراف = 0;

	برائے (cp = str; *cp && *cp != '='; ++cp)
		;
	اگر (*cp != '=') {
		errno = EINVAL;
		واپس (-1);			/* missing `=' in string */
	}

	اگر (__findenv(str, (صحیح)(cp - str), &انحراف) != تہی) {
		environ[انحراف++] = str;
		/* could be set multiple times */
		جب (__findenv(str, (صحیح)(cp - str), &انحراف)) {
			برائے (P = &environ[انحراف];; ++P)
				اگر (!(*P = *(P + 1)))
					توڑو;
		}
		واپس (0);
	}

	/* create new slot for string */
	برائے (P = environ; *P != تہی; P++)
		;
	cnt = P - environ;
	P = (حرف **)realloc(lastenv, حجم(حرف *) * (cnt + 2));
	اگر (!P)
		واپس (-1);
	اگر (lastenv != environ)
		حافظہ_نقل(P, environ, cnt * حجم(حرف *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = تہی;
	واپس (0);
}

#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
صحیح
setenv(ثابت حرف *name, ثابت حرف *قدر, صحیح rewrite)
{
	حرف *C, **P;
	ثابت حرف *np;
	صحیح l_قدر, انحراف = 0;

	برائے (np = name; *np && *np != '='; ++np)
		;
#اگر_تعریف_شدہ notyet
	اگر (*np) {
		errno = EINVAL;
		واپس (-1);			/* has `=' in name */
	}
#اگر_ختم

	l_قدر = لڑی_لمبائی(قدر);
	اگر ((C = __findenv(name, (صحیح)(np - name), &انحراف)) != تہی) {
		صحیح tmpoff = انحراف + 1;
		اگر (!rewrite)
			واپس (0);
#اگر 0 /* XXX - existing entry may not be writable */
		اگر (لڑی_لمبائی(C) >= l_قدر) {	/* old larger; copy over */
			جب ((*C++ = *قدر++))
				;
			واپس (0);
		}
#اگر_ختم
		/* could be set multiple times */
		جب (__findenv(name, (صحیح)(np - name), &tmpoff)) {
			برائے (P = &environ[tmpoff];; ++P)
				اگر (!(*P = *(P + 1)))
					توڑو;
		}
	} ورنہ {					/* create new slot */
		سائز_t cnt;

		برائے (P = environ; *P != تہی; P++)
			;
		cnt = P - environ;
		P = (حرف **)realloc(lastenv, حجم(حرف *) * (cnt + 2));
		اگر (!P)
			واپس (-1);
		اگر (lastenv != environ)
			حافظہ_نقل(P, environ, cnt * حجم(حرف *));
		lastenv = environ = P;
		انحراف = cnt;
		environ[cnt + 1] = تہی;
	}
	اگر (!(environ[انحراف] =			/* name + `=' + value */
	    حافظہ_دو((سائز_t)((صحیح)(np - name) + l_قدر + 2))))
		واپس (-1);
	برائے (C = environ[انحراف]; (*C = *name++) && *C != '='; ++C)
		;
	برائے (*C++ = '='; (*C++ = *قدر++); )
		;
	واپس (0);
}

#اگر_ختم /* HAVE_SETENV */

#اگر_غیر_تعریف_شدہ HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
صحیح
unsetenv(ثابت حرف *name)
{
	حرف **P;
	ثابت حرف *np;
	صحیح انحراف = 0;

	اگر (!name || !*name) {
		errno = EINVAL;
		واپس (-1);
	}
	برائے (np = name; *np && *np != '='; ++np)
		;
	اگر (*np) {
		errno = EINVAL;
		واپس (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	جب (__findenv(name, (صحیح)(np - name), &انحراف)) {
		برائے (P = &environ[انحراف];; ++P)
			اگر (!(*P = *(P + 1)))
				توڑو;
	}
	واپس (0);
}
#اگر_ختم /* HAVE_UNSETENV */

#اگر_ختم /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

