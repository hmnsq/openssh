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

#అన్తర్భావ "includes.h"

#ఒకవేళ !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

బాహ్య అక్షరం **environ;
#నిర్వచితం_కాకపోతే HAVE_SETENV
స్థిర అక్షరం **lastenv;				/* last value of environ */
#అయితే_ముగింపు

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
స్థిర అక్షరం *
__findenv(స్థిరరాశి అక్షరం *name, పూర్ణాంకం len, పూర్ణాంకం *స్థానభ్రంశం)
{
	బాహ్య అక్షరం **environ;
	పూర్ణాంకం i;
	స్థిరరాశి అక్షరం *np;
	అక్షరం **p, *cp;

	ఒకవేళ (name == ఖాళీ || environ == ఖాళీ)
		తిరిగి (ఖాళీ);
	కొరకు (p = environ + *స్థానభ్రంశం; (cp = *p) != ఖాళీ; ++p) {
		కొరకు (np = name, i = len; i && *cp; i--)
			ఒకవేళ (*cp++ != *np++)
				ఆపు;
		ఒకవేళ (i == 0 && *cp++ == '=') {
			*స్థానభ్రంశం = p - environ;
			తిరిగి (cp);
		}
	}
	తిరిగి (ఖాళీ);
}

#ఒకవేళ 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
పూర్ణాంకం
putenv(అక్షరం *str)
{
	అక్షరం **P, *cp;
	కొలత_t cnt;
	పూర్ణాంకం స్థానభ్రంశం = 0;

	కొరకు (cp = str; *cp && *cp != '='; ++cp)
		;
	ఒకవేళ (*cp != '=') {
		errno = EINVAL;
		తిరిగి (-1);			/* missing `=' in string */
	}

	ఒకవేళ (__findenv(str, (పూర్ణాంకం)(cp - str), &స్థానభ్రంశం) != ఖాళీ) {
		environ[స్థానభ్రంశం++] = str;
		/* could be set multiple times */
		అయితే (__findenv(str, (పూర్ణాంకం)(cp - str), &స్థానభ్రంశం)) {
			కొరకు (P = &environ[స్థానభ్రంశం];; ++P)
				ఒకవేళ (!(*P = *(P + 1)))
					ఆపు;
		}
		తిరిగి (0);
	}

	/* create new slot for string */
	కొరకు (P = environ; *P != ఖాళీ; P++)
		;
	cnt = P - environ;
	P = (అక్షరం **)realloc(lastenv, పరిమాణం(అక్షరం *) * (cnt + 2));
	ఒకవేళ (!P)
		తిరిగి (-1);
	ఒకవేళ (lastenv != environ)
		జ్ఞాపకం_నకలు(P, environ, cnt * పరిమాణం(అక్షరం *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = ఖాళీ;
	తిరిగి (0);
}

#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
పూర్ణాంకం
setenv(స్థిరరాశి అక్షరం *name, స్థిరరాశి అక్షరం *విలువ, పూర్ణాంకం rewrite)
{
	అక్షరం *C, **P;
	స్థిరరాశి అక్షరం *np;
	పూర్ణాంకం l_విలువ, స్థానభ్రంశం = 0;

	కొరకు (np = name; *np && *np != '='; ++np)
		;
#నిర్వచితమైతే notyet
	ఒకవేళ (*np) {
		errno = EINVAL;
		తిరిగి (-1);			/* has `=' in name */
	}
#అయితే_ముగింపు

	l_విలువ = అక్షరశ్రేణి_పొడవు(విలువ);
	ఒకవేళ ((C = __findenv(name, (పూర్ణాంకం)(np - name), &స్థానభ్రంశం)) != ఖాళీ) {
		పూర్ణాంకం tmpoff = స్థానభ్రంశం + 1;
		ఒకవేళ (!rewrite)
			తిరిగి (0);
#ఒకవేళ 0 /* XXX - existing entry may not be writable */
		ఒకవేళ (అక్షరశ్రేణి_పొడవు(C) >= l_విలువ) {	/* old larger; copy over */
			అయితే ((*C++ = *విలువ++))
				;
			తిరిగి (0);
		}
#అయితే_ముగింపు
		/* could be set multiple times */
		అయితే (__findenv(name, (పూర్ణాంకం)(np - name), &tmpoff)) {
			కొరకు (P = &environ[tmpoff];; ++P)
				ఒకవేళ (!(*P = *(P + 1)))
					ఆపు;
		}
	} లేకపోతే {					/* create new slot */
		కొలత_t cnt;

		కొరకు (P = environ; *P != ఖాళీ; P++)
			;
		cnt = P - environ;
		P = (అక్షరం **)realloc(lastenv, పరిమాణం(అక్షరం *) * (cnt + 2));
		ఒకవేళ (!P)
			తిరిగి (-1);
		ఒకవేళ (lastenv != environ)
			జ్ఞాపకం_నకలు(P, environ, cnt * పరిమాణం(అక్షరం *));
		lastenv = environ = P;
		స్థానభ్రంశం = cnt;
		environ[cnt + 1] = ఖాళీ;
	}
	ఒకవేళ (!(environ[స్థానభ్రంశం] =			/* name + `=' + value */
	    జ్ఞాపకం_ఇవ్వు((కొలత_t)((పూర్ణాంకం)(np - name) + l_విలువ + 2))))
		తిరిగి (-1);
	కొరకు (C = environ[స్థానభ్రంశం]; (*C = *name++) && *C != '='; ++C)
		;
	కొరకు (*C++ = '='; (*C++ = *విలువ++); )
		;
	తిరిగి (0);
}

#అయితే_ముగింపు /* HAVE_SETENV */

#నిర్వచితం_కాకపోతే HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
పూర్ణాంకం
unsetenv(స్థిరరాశి అక్షరం *name)
{
	అక్షరం **P;
	స్థిరరాశి అక్షరం *np;
	పూర్ణాంకం స్థానభ్రంశం = 0;

	ఒకవేళ (!name || !*name) {
		errno = EINVAL;
		తిరిగి (-1);
	}
	కొరకు (np = name; *np && *np != '='; ++np)
		;
	ఒకవేళ (*np) {
		errno = EINVAL;
		తిరిగి (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	అయితే (__findenv(name, (పూర్ణాంకం)(np - name), &స్థానభ్రంశం)) {
		కొరకు (P = &environ[స్థానభ్రంశం];; ++P)
			ఒకవేళ (!(*P = *(P + 1)))
				ఆపు;
	}
	తిరిగి (0);
}
#అయితే_ముగింపు /* HAVE_UNSETENV */

#అయితే_ముగింపు /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

