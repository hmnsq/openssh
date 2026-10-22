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

#إذا !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#ضمن <errno.h>
#ضمن <stdlib.h>
#ضمن <string.h>

خارجي حرف **environ;
#جيڪڏهن_وصف_نه_ٿيل HAVE_SETENV
ساكن حرف **lastenv;				/* last value of environ */
#جيڪڏهن_پورو

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
__findenv(ثابت حرف *name, صحيح len, صحيح *وٿي)
{
	خارجي حرف **environ;
	صحيح i;
	ثابت حرف *np;
	حرف **p, *cp;

	إذا (name == عدم || environ == عدم)
		أرجع (عدم);
	لكل (p = environ + *وٿي; (cp = *p) != عدم; ++p) {
		لكل (np = name, i = len; i && *cp; i--)
			إذا (*cp++ != *np++)
				اكسر;
		إذا (i == 0 && *cp++ == '=') {
			*وٿي = p - environ;
			أرجع (cp);
		}
	}
	أرجع (عدم);
}

#إذا 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
صحيح
putenv(حرف *str)
{
	حرف **P, *cp;
	سائيز_t cnt;
	صحيح وٿي = 0;

	لكل (cp = str; *cp && *cp != '='; ++cp)
		;
	إذا (*cp != '=') {
		errno = EINVAL;
		أرجع (-1);			/* missing `=' in string */
	}

	إذا (__findenv(str, (صحيح)(cp - str), &وٿي) != عدم) {
		environ[وٿي++] = str;
		/* could be set multiple times */
		طالما (__findenv(str, (صحيح)(cp - str), &وٿي)) {
			لكل (P = &environ[وٿي];; ++P)
				إذا (!(*P = *(P + 1)))
					اكسر;
		}
		أرجع (0);
	}

	/* create new slot for string */
	لكل (P = environ; *P != عدم; P++)
		;
	cnt = P - environ;
	P = (حرف **)realloc(lastenv, حجم(حرف *) * (cnt + 2));
	إذا (!P)
		أرجع (-1);
	إذا (lastenv != environ)
		يادگيري_نقل(P, environ, cnt * حجم(حرف *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = عدم;
	أرجع (0);
}

#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
صحيح
setenv(ثابت حرف *name, ثابت حرف *قدر, صحيح rewrite)
{
	حرف *C, **P;
	ثابت حرف *np;
	صحيح l_قدر, وٿي = 0;

	لكل (np = name; *np && *np != '='; ++np)
		;
#جيڪڏهن_وصف_ٿيل notyet
	إذا (*np) {
		errno = EINVAL;
		أرجع (-1);			/* has `=' in name */
	}
#جيڪڏهن_پورو

	l_قدر = لڙي_ڊيگهه(قدر);
	إذا ((C = __findenv(name, (صحيح)(np - name), &وٿي)) != عدم) {
		صحيح tmpoff = وٿي + 1;
		إذا (!rewrite)
			أرجع (0);
#إذا 0 /* XXX - existing entry may not be writable */
		إذا (لڙي_ڊيگهه(C) >= l_قدر) {	/* old larger; copy over */
			طالما ((*C++ = *قدر++))
				;
			أرجع (0);
		}
#جيڪڏهن_پورو
		/* could be set multiple times */
		طالما (__findenv(name, (صحيح)(np - name), &tmpoff)) {
			لكل (P = &environ[tmpoff];; ++P)
				إذا (!(*P = *(P + 1)))
					اكسر;
		}
	} وإلا {					/* create new slot */
		سائيز_t cnt;

		لكل (P = environ; *P != عدم; P++)
			;
		cnt = P - environ;
		P = (حرف **)realloc(lastenv, حجم(حرف *) * (cnt + 2));
		إذا (!P)
			أرجع (-1);
		إذا (lastenv != environ)
			يادگيري_نقل(P, environ, cnt * حجم(حرف *));
		lastenv = environ = P;
		وٿي = cnt;
		environ[cnt + 1] = عدم;
	}
	إذا (!(environ[وٿي] =			/* name + `=' + value */
	    يادگيري_ڏيو((سائيز_t)((صحيح)(np - name) + l_قدر + 2))))
		أرجع (-1);
	لكل (C = environ[وٿي]; (*C = *name++) && *C != '='; ++C)
		;
	لكل (*C++ = '='; (*C++ = *قدر++); )
		;
	أرجع (0);
}

#جيڪڏهن_پورو /* HAVE_SETENV */

#جيڪڏهن_وصف_نه_ٿيل HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
صحيح
unsetenv(ثابت حرف *name)
{
	حرف **P;
	ثابت حرف *np;
	صحيح وٿي = 0;

	إذا (!name || !*name) {
		errno = EINVAL;
		أرجع (-1);
	}
	لكل (np = name; *np && *np != '='; ++np)
		;
	إذا (*np) {
		errno = EINVAL;
		أرجع (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	طالما (__findenv(name, (صحيح)(np - name), &وٿي)) {
		لكل (P = &environ[وٿي];; ++P)
			إذا (!(*P = *(P + 1)))
				اكسر;
	}
	أرجع (0);
}
#جيڪڏهن_پورو /* HAVE_UNSETENV */

#جيڪڏهن_پورو /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

