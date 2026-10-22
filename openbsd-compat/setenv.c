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

#अन्तर्भाव "includes.h"

#जइ !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV)

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

बाह्य वर्ण **environ;
#ifndef HAVE_SETENV
स्थिर वर्ण **lastenv;				/* last value of environ */
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
स्थिर वर्ण *
__findenv(ध्रुव वर्ण *name, पूर्णाङ्क len, पूर्णाङ्क *offset)
{
	बाह्य वर्ण **environ;
	पूर्णाङ्क i;
	ध्रुव वर्ण *np;
	वर्ण **p, *cp;

	जइ (name == रिक्त || environ == रिक्त)
		प्रत्यागम (रिक्त);
	प्रति (p = environ + *offset; (cp = *p) != रिक्त; ++p) {
		प्रति (np = name, i = len; i && *cp; i--)
			जइ (*cp++ != *np++)
				भङ्ग;
		जइ (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			प्रत्यागम (cp);
		}
	}
	प्रत्यागम (रिक्त);
}

#जइ 0 /* nothing uses putenv */
/*
 * putenv --
 *	Add a name=value string directly to the environmental, replacing
 *	any current value.
 */
पूर्णाङ्क
putenv(वर्ण *str)
{
	वर्ण **P, *cp;
	size_t cnt;
	पूर्णाङ्क offset = 0;

	प्रति (cp = str; *cp && *cp != '='; ++cp)
		;
	जइ (*cp != '=') {
		errno = EINVAL;
		प्रत्यागम (-1);			/* missing `=' in string */
	}

	जइ (__findenv(str, (पूर्णाङ्क)(cp - str), &offset) != रिक्त) {
		environ[offset++] = str;
		/* could be set multiple times */
		जाव (__findenv(str, (पूर्णाङ्क)(cp - str), &offset)) {
			प्रति (P = &environ[offset];; ++P)
				जइ (!(*P = *(P + 1)))
					भङ्ग;
		}
		प्रत्यागम (0);
	}

	/* create new slot for string */
	प्रति (P = environ; *P != रिक्त; P++)
		;
	cnt = P - environ;
	P = (वर्ण **)realloc(lastenv, परिमाण(वर्ण *) * (cnt + 2));
	जइ (!P)
		प्रत्यागम (-1);
	जइ (lastenv != environ)
		memcpy(P, environ, cnt * परिमाण(वर्ण *));
	lastenv = environ = P;
	environ[cnt] = str;
	environ[cnt + 1] = रिक्त;
	प्रत्यागम (0);
}

#endif

#ifndef HAVE_SETENV
/*
 * setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
पूर्णाङ्क
setenv(ध्रुव वर्ण *name, ध्रुव वर्ण *मानम्, पूर्णाङ्क rewrite)
{
	वर्ण *C, **P;
	ध्रुव वर्ण *np;
	पूर्णाङ्क l_मानम्, offset = 0;

	प्रति (np = name; *np && *np != '='; ++np)
		;
#ifdef notyet
	जइ (*np) {
		errno = EINVAL;
		प्रत्यागम (-1);			/* has `=' in name */
	}
#endif

	l_मानम् = strlen(मानम्);
	जइ ((C = __findenv(name, (पूर्णाङ्क)(np - name), &offset)) != रिक्त) {
		पूर्णाङ्क tmpoff = offset + 1;
		जइ (!rewrite)
			प्रत्यागम (0);
#जइ 0 /* XXX - existing entry may not be writable */
		जइ (strlen(C) >= l_मानम्) {	/* old larger; copy over */
			जाव ((*C++ = *मानम्++))
				;
			प्रत्यागम (0);
		}
#endif
		/* could be set multiple times */
		जाव (__findenv(name, (पूर्णाङ्क)(np - name), &tmpoff)) {
			प्रति (P = &environ[tmpoff];; ++P)
				जइ (!(*P = *(P + 1)))
					भङ्ग;
		}
	} अण्णहा {					/* create new slot */
		size_t cnt;

		प्रति (P = environ; *P != रिक्त; P++)
			;
		cnt = P - environ;
		P = (वर्ण **)realloc(lastenv, परिमाण(वर्ण *) * (cnt + 2));
		जइ (!P)
			प्रत्यागम (-1);
		जइ (lastenv != environ)
			memcpy(P, environ, cnt * परिमाण(वर्ण *));
		lastenv = environ = P;
		offset = cnt;
		environ[cnt + 1] = रिक्त;
	}
	जइ (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((पूर्णाङ्क)(np - name) + l_मानम् + 2))))
		प्रत्यागम (-1);
	प्रति (C = environ[offset]; (*C = *name++) && *C != '='; ++C)
		;
	प्रति (*C++ = '='; (*C++ = *मानम्++); )
		;
	प्रत्यागम (0);
}

#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
/*
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
पूर्णाङ्क
unsetenv(ध्रुव वर्ण *name)
{
	वर्ण **P;
	ध्रुव वर्ण *np;
	पूर्णाङ्क offset = 0;

	जइ (!name || !*name) {
		errno = EINVAL;
		प्रत्यागम (-1);
	}
	प्रति (np = name; *np && *np != '='; ++np)
		;
	जइ (*np) {
		errno = EINVAL;
		प्रत्यागम (-1);			/* has `=' in name */
	}

	/* could be set multiple times */
	जाव (__findenv(name, (पूर्णाङ्क)(np - name), &offset)) {
		प्रति (P = &environ[offset];; ++P)
			जइ (!(*P = *(P + 1)))
				भङ्ग;
	}
	प्रत्यागम (0);
}
#endif /* HAVE_UNSETENV */

#endif /* !defined(HAVE_SETENV) || !defined(HAVE_UNSETENV) */

