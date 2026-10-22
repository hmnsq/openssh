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

#অন্তর্ভাব "includes.h"

#যদি 0
#অন্তর্ভাব "file.h"
#endif

#যদি !defined(HAVE_GETLINE) || defined(BROKEN_GETLINE)
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <string.h>

স্থির ssize_t
getdelim(অক্ষর **buf, আকার_t *bufsiz, পূর্ণসংখ্যা delimiter, FILE *fp)
{
	অক্ষর *ptr, *eptr;


	যদি (*buf == ফাঁকা || *bufsiz == 0) {
		যদি ((*buf = malloc(BUFSIZ)) == ফাঁকা)
			ফেরত -1;
		*bufsiz = BUFSIZ;
	}

	জন্য (ptr = *buf, eptr = *buf + *bufsiz;;) {
		পূর্ণসংখ্যা c = fgetc(fp);
		যদি (c == -1) {
			যদি (feof(fp)) {
				ssize_t diff = (ssize_t)(ptr - *buf);
				যদি (diff != 0) {
					*ptr = '\0';
					ফেরত diff;
				}
			}
			ফেরত -1;
		}
		*ptr++ = c;
		যদি (c == delimiter) {
			*ptr = '\0';
			ফেরত ptr - *buf;
		}
		যদি (ptr + 2 >= eptr) {
			অক্ষর *nbuf;
			আকার_t nbufsiz = *bufsiz * 2;
			ssize_t d = ptr - *buf;
			যদি ((nbuf = realloc(*buf, nbufsiz)) == ফাঁকা)
				ফেরত -1;
			*buf = nbuf;
			*bufsiz = nbufsiz;
			eptr = nbuf + nbufsiz;
			ptr = nbuf + d;
		}
	}
}

ssize_t
getline(অক্ষর **buf, আকার_t *bufsiz, FILE *fp)
{
	ফেরত getdelim(buf, bufsiz, '\n', fp);
}

#endif

#ifdef TEST
পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা argc, অক্ষর *argv[])
{
	অক্ষর *p = ফাঁকা;
	ssize_t len;
	আকার_t n = 0;

	যখন ((len = getline(&p, &n, stdin)) != -1)
		(শূন্য)printf("%" আকার_T_FORMAT "d %s", len, p);
	মুক্ত(p);
	ফেরত 0;
}
#endif
