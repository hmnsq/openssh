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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଯଦି 0
#ଅନ୍ତର୍ଭାଵ "file.h"
#endif

#ଯଦି !defined(HAVE_GETLINE) || defined(BROKEN_GETLINE)
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

ସ୍ଥିର ssize_t
getdelim(ଅକ୍ଷର **buf, size_t *bufsiz, ପୂର୍ଣ୍ଣସଂଖ୍ୟା delimiter, FILE *fp)
{
	ଅକ୍ଷର *ptr, *eptr;


	ଯଦି (*buf == ଖାଲି || *bufsiz == 0) {
		ଯଦି ((*buf = malloc(BUFSIZ)) == ଖାଲି)
			ଫେରନ୍ତୁ -1;
		*bufsiz = BUFSIZ;
	}

	ପାଇଁ (ptr = *buf, eptr = *buf + *bufsiz;;) {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା c = fgetc(fp);
		ଯଦି (c == -1) {
			ଯଦି (feof(fp)) {
				ssize_t diff = (ssize_t)(ptr - *buf);
				ଯଦି (diff != 0) {
					*ptr = '\0';
					ଫେରନ୍ତୁ diff;
				}
			}
			ଫେରନ୍ତୁ -1;
		}
		*ptr++ = c;
		ଯଦି (c == delimiter) {
			*ptr = '\0';
			ଫେରନ୍ତୁ ptr - *buf;
		}
		ଯଦି (ptr + 2 >= eptr) {
			ଅକ୍ଷର *nbuf;
			size_t nbufsiz = *bufsiz * 2;
			ssize_t d = ptr - *buf;
			ଯଦି ((nbuf = realloc(*buf, nbufsiz)) == ଖାଲି)
				ଫେରନ୍ତୁ -1;
			*buf = nbuf;
			*bufsiz = nbufsiz;
			eptr = nbuf + nbufsiz;
			ptr = nbuf + d;
		}
	}
}

ssize_t
getline(ଅକ୍ଷର **buf, size_t *bufsiz, FILE *fp)
{
	ଫେରନ୍ତୁ getdelim(buf, bufsiz, '\n', fp);
}

#endif

#ifdef TEST
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର *argv[])
{
	ଅକ୍ଷର *p = ଖାଲି;
	ssize_t len;
	size_t n = 0;

	ଯେତେବେଳେ ((len = getline(&p, &n, stdin)) != -1)
		(ଶୂନ୍ୟ)printf("%" SIZE_T_FORMAT "d %s", len, p);
	ମୁକ୍ତ(p);
	ଫେରନ୍ତୁ 0;
}
#endif
