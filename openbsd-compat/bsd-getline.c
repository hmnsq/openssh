/*	$NetBSD: getline.c,v 1.1.1.6 2015/01/02 20:34:27 christos Exp $	*/

/*	NetBSD: getline.c,v 1.2 2014/09/16 17:23:50 christos Exp 	*/

/*-
 * Copyright (c) 2011 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* NETBSD ORIGINAL: external/bsd/file/dist/src/getline.c */

#अन्तर्भाव "includes.h"

#जइ 0
#अन्तर्भाव "file.h"
#endif

#जइ !defined(HAVE_GETLINE) || defined(BROKEN_GETLINE)
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <string.h>

स्थिर ssize_t
getdelim(वर्ण **buf, size_t *bufsiz, पूर्णाङ्क delimiter, FILE *fp)
{
	वर्ण *ptr, *eptr;


	जइ (*buf == रिक्त || *bufsiz == 0) {
		जइ ((*buf = malloc(BUFSIZ)) == रिक्त)
			प्रत्यागम -1;
		*bufsiz = BUFSIZ;
	}

	प्रति (ptr = *buf, eptr = *buf + *bufsiz;;) {
		पूर्णाङ्क c = fgetc(fp);
		जइ (c == -1) {
			जइ (feof(fp)) {
				ssize_t diff = (ssize_t)(ptr - *buf);
				जइ (diff != 0) {
					*ptr = '\0';
					प्रत्यागम diff;
				}
			}
			प्रत्यागम -1;
		}
		*ptr++ = c;
		जइ (c == delimiter) {
			*ptr = '\0';
			प्रत्यागम ptr - *buf;
		}
		जइ (ptr + 2 >= eptr) {
			वर्ण *nbuf;
			size_t nbufsiz = *bufsiz * 2;
			ssize_t d = ptr - *buf;
			जइ ((nbuf = realloc(*buf, nbufsiz)) == रिक्त)
				प्रत्यागम -1;
			*buf = nbuf;
			*bufsiz = nbufsiz;
			eptr = nbuf + nbufsiz;
			ptr = nbuf + d;
		}
	}
}

ssize_t
getline(वर्ण **buf, size_t *bufsiz, FILE *fp)
{
	प्रत्यागम getdelim(buf, bufsiz, '\n', fp);
}

#endif

#ifdef TEST
पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण *argv[])
{
	वर्ण *p = रिक्त;
	ssize_t len;
	size_t n = 0;

	जाव ((len = getline(&p, &n, stdin)) != -1)
		(शून्य)printf("%" SIZE_T_FORMAT "d %s", len, p);
	मुक्त(p);
	प्रत्यागम 0;
}
#endif
