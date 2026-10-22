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

বাহ্য বর্ণ **environ;
#ifndef HAVE_SETENV
স্থির বর্ণ **lastenv;				/* last value of environ */
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
স্থির বর্ণ *
__findenv(ধ্রুব বর্ণ *name, পূর্ণাঙ্ক len, পূর্ণাঙ্ক *offset)
{
	বাহ্য বর্ণ **environ;
	পূর্ণাঙ্ক i;
	ধ্রুব বর্ণ *np;
	বর্ণ **p, *cp;

	যদি (name == রিক্ত || environ == রিক্ত)
		প্রত্যাগম (রিক্ত);
	প্রতি (p = environ + *offset; (cp = *p) != রিক্ত; ++p) {
		প্রতি (np = name, i = len; i && *cp; i--)
			যদি (*cp++ != *np++)
				ভঙ্গ;
		যদি (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			প্রত্যাগম (cp);
		}
	}
	প্রত্যাগম (রিক্ত);
}

#যদি 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
পূর্ণাঙ্ক
putenv(বর্ণ *str)
{
	বর্ণ **P, *cp;
	size_t cnt;
	পূর্ণাঙ্ক offset = 0;

	প্রতি (cp = str; *cp && *cp != '='; ++cp)
		;
	যদি (*cp != '=') {
		errno = EINVAL;
		প্রত্যাগম (-1);			/* missing `=' in string */
	}

	যদি (__findenv(str, (পূর্ণাঙ্ক)(cp - str), &offset) != রিক্ত) {
		environ[offset++] = str;
		/* could be set multiple times */
		যাবত্ (__findenv(str, (পূর্ণাঙ্ক)(cp - str), &offset)) {
			প্রতি (P = &environ[offset];; ++P)
				যদি (!(*P = *(P + 1)))
					ভঙ্গ;
		}
		প্রত্যাগম (0);
	}

	/* create new slot for string */
	প্রতি (P = environ; *P != রিক্ত; P++)
		;
	cnt = P - environ;
	P = (বর্ণ **)realloc(lastenv, পরিমাণ(বর্ণ *) * (cnt + 2));
	যদি (!P)
		প্রত্যাগম (-1);
	যদি (lastenv != environ)
		memcpy(P, environ, cnt * পরিমাণ(বর্ণ *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = রিক্ত;
	প্রত্যাগম (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
পূর্ণাঙ্ক
setenv(ধ্রুব বর্ণ *name, ধ্রুব বর্ণ *মান, পূর্ণাঙ্ক rewrite)
{
	বর্ণ *C, **P;
	ধ্রুব বর্ণ *np;
	পূর্ণাঙ্ক l_মান, offset = 0;

	প্রতি (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	যদি (*np) {
		errno = EINVAL;
		প্রত্যাগম (-1);			/* has `=' in name */
	}
#endif

	l_মান = strlen(মান);
	যদি ((C = __findenv(name, (পূর্ণাঙ্ক)(np - name), &offset)) != রিক্ত) {
		পূর্ণাঙ্ক tmpoff = offset + 1;
		যদি (!rewrite)
			প্রত্যাগম (0);
#যদি 0 /* XXX - existing entry may not be writable */
		যদি (strlen(C) >= l_মান) {	/* old larger; copy over */
			যাবত্ ((*C++ = *মান++))
				;
			প্রত্যাগম (0);
		}
#endif
		/* could be set multiple times */
		যাবত্ (__findenv(name, (পূর্ণাঙ্ক)(np - name), &tmpoff)) {
			প্রতি (P = &environ[tmpoff];; ++P)
				যদি (!(*P = *(P + 1)))
					ভঙ্গ;
		}
	} অন্যথা {					/* create new slot */
		size_t cnt;

		প্রতি (P = environ; *P != রিক্ত; P++)
			;
		cnt = P - environ;
		P = (বর্ণ **)realloc(lastenv, পরিমাণ(বর্ণ *) * (cnt + 2));
		যদি (!P)
			প্রত্যাগম (-1);
		যদি (lastenv != environ)
			memcpy(P, environ, cnt * পরিমাণ(বর্ণ *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = রিক্ত;
	}
	যদি (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((পূর্ণাঙ্ক)(np - name) + l_মান + 2))))
		প্রত্যাগম (-1);
	প্রতি (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	প্রতি (*C++ = '='; (*C++ = *মান++); )
		;
	প্রত্যাগম (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
পূর্ণাঙ্ক
unsetenv(ধ্রুব বর্ণ *name)
{
	বর্ণ **P;
	ধ্রুব বর্ণ *np;
	পূর্ণাঙ্ক offset = 0;

	যদি (!name || !*name) {
		errno = EINVAL;
		প্রত্যাগম (-1);
	}
	প্রতি (np = name; *np && *np != '='; ++np)
		;
	যদি (*np) {
		errno = EINVAL;
		প্রত্যাগম (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	যাবত্ (__findenv(name, (পূর্ণাঙ্ক)(np - name), &offset)) {
		প্রতি (P = &environ[offset];; ++P)
			যদি (!(*P = *(P + 1)))
				ভঙ্গ;
	}
	প্রত্যাগম (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

