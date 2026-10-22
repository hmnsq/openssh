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

#অন্তর্ভাব "includes.h"

#যদি !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

বাহ্যিক অক্ষর **environ;
#ifndef HAVE_SETENV
স্থির অক্ষর **lastenv;				/* last value of environ */
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
স্থির অক্ষর *
__findenv(ধ্রুবক অক্ষর *name, পূর্ণসংখ্যা len, পূর্ণসংখ্যা *offset)
{
	বাহ্যিক অক্ষর **environ;
	পূর্ণসংখ্যা i;
	ধ্রুবক অক্ষর *np;
	অক্ষর **p, *cp;

	যদি (name == ফাঁকা || environ == ফাঁকা)
		ফেরত (ফাঁকা);
	জন্য (p = environ + *offset; (cp = *p) != ফাঁকা; ++p) {
		জন্য (np = name, i = len; i && *cp; i--)
			যদি (*cp++ != *np++)
				বিরতি;
		যদি (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			ফেরত (cp);
		}
	}
	ফেরত (ফাঁকা);
}

#যদি 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
পূর্ণসংখ্যা
putenv(অক্ষর *str)
{
	অক্ষর **P, *cp;
	আকার_t cnt;
	পূর্ণসংখ্যা offset = 0;

	জন্য (cp = str; *cp && *cp != '='; ++cp)
		;
	যদি (*cp != '=') {
		errno = EINVAL;
		ফেরত (-1);			/* missing `=' in string */
	}

	যদি (__findenv(str, (পূর্ণসংখ্যা)(cp - str), &offset) != ফাঁকা) {
		environ[offset++] = str;
		/* could be set multiple times */
		যখন (__findenv(str, (পূর্ণসংখ্যা)(cp - str), &offset)) {
			জন্য (P = &environ[offset];; ++P)
				যদি (!(*P = *(P + 1)))
					বিরতি;
		}
		ফেরত (0);
	}

	/* create new slot for string */
	জন্য (P = environ; *P != ফাঁকা; P++)
		;
	cnt = P - environ;
	P = (অক্ষর **)realloc(lastenv, আকার(অক্ষর *) * (cnt + 2));
	যদি (!P)
		ফেরত (-1);
	যদি (lastenv != environ)
		memcpy(P, environ, cnt * আকার(অক্ষর *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = ফাঁকা;
	ফেরত (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
পূর্ণসংখ্যা
setenv(ধ্রুবক অক্ষর *name, ধ্রুবক অক্ষর *মান, পূর্ণসংখ্যা rewrite)
{
	অক্ষর *C, **P;
	ধ্রুবক অক্ষর *np;
	পূর্ণসংখ্যা l_মান, offset = 0;

	জন্য (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	যদি (*np) {
		errno = EINVAL;
		ফেরত (-1);			/* has `=' in name */
	}
#endif

	l_মান = strlen(মান);
	যদি ((C = __findenv(name, (পূর্ণসংখ্যা)(np - name), &offset)) != ফাঁকা) {
		পূর্ণসংখ্যা tmpoff = offset + 1;
		যদি (!rewrite)
			ফেরত (0);
#যদি 0 /* XXX - existing entry may not be writable */
		যদি (strlen(C) >= l_মান) {	/* old larger; copy over */
			যখন ((*C++ = *মান++))
				;
			ফেরত (0);
		}
#endif
		/* could be set multiple times */
		যখন (__findenv(name, (পূর্ণসংখ্যা)(np - name), &tmpoff)) {
			জন্য (P = &environ[tmpoff];; ++P)
				যদি (!(*P = *(P + 1)))
					বিরতি;
		}
	} অন্যথা {					/* create new slot */
		আকার_t cnt;

		জন্য (P = environ; *P != ফাঁকা; P++)
			;
		cnt = P - environ;
		P = (অক্ষর **)realloc(lastenv, আকার(অক্ষর *) * (cnt + 2));
		যদি (!P)
			ফেরত (-1);
		যদি (lastenv != environ)
			memcpy(P, environ, cnt * আকার(অক্ষর *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = ফাঁকা;
	}
	যদি (!(environ[offset] =			/* name + `=' + value */
	    malloc((আকার_t)((পূর্ণসংখ্যা)(np - name) + l_মান + 2))))
		ফেরত (-1);
	জন্য (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	জন্য (*C++ = '='; (*C++ = *মান++); )
		;
	ফেরত (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
পূর্ণসংখ্যা
unsetenv(ধ্রুবক অক্ষর *name)
{
	অক্ষর **P;
	ধ্রুবক অক্ষর *np;
	পূর্ণসংখ্যা offset = 0;

	যদি (!name || !*name) {
		errno = EINVAL;
		ফেরত (-1);
	}
	জন্য (np = name; *np && *np != '='; ++np)
		;
	যদি (*np) {
		errno = EINVAL;
		ফেরত (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	যখন (__findenv(name, (পূর্ণসংখ্যা)(np - name), &offset)) {
		জন্য (P = &environ[offset];; ++P)
			যদি (!(*P = *(P + 1)))
				বিরতি;
	}
	ফেরত (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

