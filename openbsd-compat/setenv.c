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

#অন্তর্ভাৱ "includes.h"

#যদি !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

বাহ্য ৱর্ণ **environ;
#ifndef HAVE_SETENV
স্থির ৱর্ণ **lastenv;				/* last value of environ */
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
স্থির ৱর্ণ *
__findenv(ধ্রুৱ ৱর্ণ *name, পূর্ণাঙ্ক len, পূর্ণাঙ্ক *offset)
{
	বাহ্য ৱর্ণ **environ;
	পূর্ণাঙ্ক i;
	ধ্রুৱ ৱর্ণ *np;
	ৱর্ণ **p, *cp;

	যদি (name == রিক্ত || environ == রিক্ত)
		ঘূৰাই (রিক্ত);
	বাবে (p = environ + *offset; (cp = *p) != রিক্ত; ++p) {
		বাবে (np = name, i = len; i && *cp; i--)
			যদি (*cp++ != *np++)
				ভঙ্গ;
		যদি (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			ঘূৰাই (cp);
		}
	}
	ঘূৰাই (রিক্ত);
}

#যদি 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
পূর্ণাঙ্ক
putenv(ৱর্ণ *str)
{
	ৱর্ণ **P, *cp;
	size_t cnt;
	পূর্ণাঙ্ক offset = 0;

	বাবে (cp = str; *cp && *cp != '='; ++cp)
		;
	যদি (*cp != '=') {
		errno = EINVAL;
		ঘূৰাই (-1);			/* missing `=' in string */
	}

	যদি (__findenv(str, (পূর্ণাঙ্ক)(cp - str), &offset) != রিক্ত) {
		environ[offset++] = str;
		/* could be set multiple times */
		যেতিয়ালৈ (__findenv(str, (পূর্ণাঙ্ক)(cp - str), &offset)) {
			বাবে (P = &environ[offset];; ++P)
				যদি (!(*P = *(P + 1)))
					ভঙ্গ;
		}
		ঘূৰাই (0);
	}

	/* create new slot for string */
	বাবে (P = environ; *P != রিক্ত; P++)
		;
	cnt = P - environ;
	P = (ৱর্ণ **)realloc(lastenv, পরিমাণ(ৱর্ণ *) * (cnt + 2));
	যদি (!P)
		ঘূৰাই (-1);
	যদি (lastenv != environ)
		memcpy(P, environ, cnt * পরিমাণ(ৱর্ণ *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = রিক্ত;
	ঘূৰাই (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
পূর্ণাঙ্ক
setenv(ধ্রুৱ ৱর্ণ *name, ধ্রুৱ ৱর্ণ *মান, পূর্ণাঙ্ক rewrite)
{
	ৱর্ণ *C, **P;
	ধ্রুৱ ৱর্ণ *np;
	পূর্ণাঙ্ক l_মান, offset = 0;

	বাবে (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	যদি (*np) {
		errno = EINVAL;
		ঘূৰাই (-1);			/* has `=' in name */
	}
#endif

	l_মান = strlen(মান);
	যদি ((C = __findenv(name, (পূর্ণাঙ্ক)(np - name), &offset)) != রিক্ত) {
		পূর্ণাঙ্ক tmpoff = offset + 1;
		যদি (!rewrite)
			ঘূৰাই (0);
#যদি 0 /* XXX - existing entry may not be writable */
		যদি (strlen(C) >= l_মান) {	/* old larger; copy over */
			যেতিয়ালৈ ((*C++ = *মান++))
				;
			ঘূৰাই (0);
		}
#endif
		/* could be set multiple times */
		যেতিয়ালৈ (__findenv(name, (পূর্ণাঙ্ক)(np - name), &tmpoff)) {
			বাবে (P = &environ[tmpoff];; ++P)
				যদি (!(*P = *(P + 1)))
					ভঙ্গ;
		}
	} অন্যথা {					/* create new slot */
		size_t cnt;

		বাবে (P = environ; *P != রিক্ত; P++)
			;
		cnt = P - environ;
		P = (ৱর্ণ **)realloc(lastenv, পরিমাণ(ৱর্ণ *) * (cnt + 2));
		যদি (!P)
			ঘূৰাই (-1);
		যদি (lastenv != environ)
			memcpy(P, environ, cnt * পরিমাণ(ৱর্ণ *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = রিক্ত;
	}
	যদি (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((পূর্ণাঙ্ক)(np - name) + l_মান + 2))))
		ঘূৰাই (-1);
	বাবে (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	বাবে (*C++ = '='; (*C++ = *মান++); )
		;
	ঘূৰাই (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
পূর্ণাঙ্ক
unsetenv(ধ্রুৱ ৱর্ণ *name)
{
	ৱর্ণ **P;
	ধ্রুৱ ৱর্ণ *np;
	পূর্ণাঙ্ক offset = 0;

	যদি (!name || !*name) {
		errno = EINVAL;
		ঘূৰাই (-1);
	}
	বাবে (np = name; *np && *np != '='; ++np)
		;
	যদি (*np) {
		errno = EINVAL;
		ঘূৰাই (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	যেতিয়ালৈ (__findenv(name, (পূর্ণাঙ্ক)(np - name), &offset)) {
		বাবে (P = &environ[offset];; ++P)
			যদি (!(*P = *(P + 1)))
				ভঙ্গ;
	}
	ঘূৰাই (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

