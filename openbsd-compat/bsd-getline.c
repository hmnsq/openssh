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

#અન્તર્ભાવ "includes.h"

#જો 0
#અન્તર્ભાવ "file.h"
#endif

#જો !defined(HAVE_GETLINE) || defined(BROKEN_GETLINE)
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <string.h>

સ્થિર ssize_t
getdelim(અક્ષર **buf, size_t *bufsiz, પૂર્ણાંક delimiter, FILE *fp)
{
	અક્ષર *ptr, *eptr;


	જો (*buf == ખાલી || *bufsiz == 0) {
		જો ((*buf = malloc(BUFSIZ)) == ખાલી)
			પાછા -1;
		*bufsiz = BUFSIZ;
	}

	માટે (ptr = *buf, eptr = *buf + *bufsiz;;) {
		પૂર્ણાંક c = fgetc(fp);
		જો (c == -1) {
			જો (feof(fp)) {
				ssize_t diff = (ssize_t)(ptr - *buf);
				જો (diff != 0) {
					*ptr = '\0';
					પાછા diff;
				}
			}
			પાછા -1;
		}
		*ptr++ = c;
		જો (c == delimiter) {
			*ptr = '\0';
			પાછા ptr - *buf;
		}
		જો (ptr + 2 >= eptr) {
			અક્ષર *nbuf;
			size_t nbufsiz = *bufsiz * 2;
			ssize_t d = ptr - *buf;
			જો ((nbuf = realloc(*buf, nbufsiz)) == ખાલી)
				પાછા -1;
			*buf = nbuf;
			*bufsiz = nbufsiz;
			eptr = nbuf + nbufsiz;
			ptr = nbuf + d;
		}
	}
}

ssize_t
getline(અક્ષર **buf, size_t *bufsiz, FILE *fp)
{
	પાછા getdelim(buf, bufsiz, '\n', fp);
}

#endif

#ifdef TEST
પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર *argv[])
{
	અક્ષર *p = ખાલી;
	ssize_t len;
	size_t n = 0;

	જ્યારે ((len = getline(&p, &n, stdin)) != -1)
		(શૂન્ય)printf("%" SIZE_T_FORMAT "d %s", len, p);
	મુક્ત(p);
	પાછા 0;
}
#endif
