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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଯଦି !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

ବାହ୍ୟ ଅକ୍ଷର **environ;
#ifndef HAVE_SETENV
ସ୍ଥିର ଅକ୍ଷର **lastenv;				/* last value of environ */
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
ସ୍ଥିର ଅକ୍ଷର *
__findenv(ଅଚଳ ଅକ୍ଷର *name, ପୂର୍ଣ୍ଣସଂଖ୍ୟା len, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *offset)
{
	ବାହ୍ୟ ଅକ୍ଷର **environ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ଅଚଳ ଅକ୍ଷର *np;
	ଅକ୍ଷର **p, *cp;

	ଯଦି (name == ଖାଲି || environ == ଖାଲି)
		ଫେରନ୍ତୁ (ଖାଲି);
	ପାଇଁ (p = environ + *offset; (cp = *p) != ଖାଲି; ++p) {
		ପାଇଁ (np = name, i = len; i && *cp; i--)
			ଯଦି (*cp++ != *np++)
				ଭାଙ୍ଗ;
		ଯଦି (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			ଫେରନ୍ତୁ (cp);
		}
	}
	ଫେରନ୍ତୁ (ଖାଲି);
}

#ଯଦି 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
putenv(ଅକ୍ଷର *str)
{
	ଅକ୍ଷର **P, *cp;
	size_t cnt;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା offset = 0;

	ପାଇଁ (cp = str; *cp && *cp != '='; ++cp)
		;
	ଯଦି (*cp != '=') {
		errno = EINVAL;
		ଫେରନ୍ତୁ (-1);			/* missing `=' in string */
	}

	ଯଦି (__findenv(str, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)(cp - str), &offset) != ଖାଲି) {
		environ[offset++] = str;
		/* could be set multiple times */
		ଯେତେବେଳେ (__findenv(str, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)(cp - str), &offset)) {
			ପାଇଁ (P = &environ[offset];; ++P)
				ଯଦି (!(*P = *(P + 1)))
					ଭାଙ୍ଗ;
		}
		ଫେରନ୍ତୁ (0);
	}

	/* create new slot for string */
	ପାଇଁ (P = environ; *P != ଖାଲି; P++)
		;
	cnt = P - environ;
	P = (ଅକ୍ଷର **)realloc(lastenv, ଆକାର(ଅକ୍ଷର *) * (cnt + 2));
	ଯଦି (!P)
		ଫେରନ୍ତୁ (-1);
	ଯଦି (lastenv != environ)
		memcpy(P, environ, cnt * ଆକାର(ଅକ୍ଷର *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = ଖାଲି;
	ଫେରନ୍ତୁ (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
setenv(ଅଚଳ ଅକ୍ଷର *name, ଅଚଳ ଅକ୍ଷର *ମୂଲ୍ୟ, ପୂର୍ଣ୍ଣସଂଖ୍ୟା rewrite)
{
	ଅକ୍ଷର *C, **P;
	ଅଚଳ ଅକ୍ଷର *np;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା l_ମୂଲ୍ୟ, offset = 0;

	ପାଇଁ (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	ଯଦି (*np) {
		errno = EINVAL;
		ଫେରନ୍ତୁ (-1);			/* has `=' in name */
	}
#endif

	l_ମୂଲ୍ୟ = strlen(ମୂଲ୍ୟ);
	ଯଦି ((C = __findenv(name, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)(np - name), &offset)) != ଖାଲି) {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା tmpoff = offset + 1;
		ଯଦି (!rewrite)
			ଫେରନ୍ତୁ (0);
#ଯଦି 0 /* XXX - existing entry may not be writable */
		ଯଦି (strlen(C) >= l_ମୂଲ୍ୟ) {	/* old larger; copy over */
			ଯେତେବେଳେ ((*C++ = *ମୂଲ୍ୟ++))
				;
			ଫେରନ୍ତୁ (0);
		}
#endif
		/* could be set multiple times */
		ଯେତେବେଳେ (__findenv(name, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)(np - name), &tmpoff)) {
			ପାଇଁ (P = &environ[tmpoff];; ++P)
				ଯଦି (!(*P = *(P + 1)))
					ଭାଙ୍ଗ;
		}
	} ଅନ୍ୟଥା {					/* create new slot */
		size_t cnt;

		ପାଇଁ (P = environ; *P != ଖାଲି; P++)
			;
		cnt = P - environ;
		P = (ଅକ୍ଷର **)realloc(lastenv, ଆକାର(ଅକ୍ଷର *) * (cnt + 2));
		ଯଦି (!P)
			ଫେରନ୍ତୁ (-1);
		ଯଦି (lastenv != environ)
			memcpy(P, environ, cnt * ଆକାର(ଅକ୍ଷର *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = ଖାଲି;
	}
	ଯଦି (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((ପୂର୍ଣ୍ଣସଂଖ୍ୟା)(np - name) + l_ମୂଲ୍ୟ + 2))))
		ଫେରନ୍ତୁ (-1);
	ପାଇଁ (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	ପାଇଁ (*C++ = '='; (*C++ = *ମୂଲ୍ୟ++); )
		;
	ଫେରନ୍ତୁ (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
unsetenv(ଅଚଳ ଅକ୍ଷର *name)
{
	ଅକ୍ଷର **P;
	ଅଚଳ ଅକ୍ଷର *np;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା offset = 0;

	ଯଦି (!name || !*name) {
		errno = EINVAL;
		ଫେରନ୍ତୁ (-1);
	}
	ପାଇଁ (np = name; *np && *np != '='; ++np)
		;
	ଯଦି (*np) {
		errno = EINVAL;
		ଫେରନ୍ତୁ (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	ଯେତେବେଳେ (__findenv(name, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)(np - name), &offset)) {
		ପାଇଁ (P = &environ[offset];; ++P)
			ଯଦି (!(*P = *(P + 1)))
				ଭାଙ୍ଗ;
	}
	ଫେରନ୍ତୁ (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

