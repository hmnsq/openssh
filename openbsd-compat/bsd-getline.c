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

#ضمن "includes.h"

#𐤀𐤌 0
#ضمن "file.h"
#endif

#𐤀𐤌 !defined(HAVE_GETLINE) || defined(BROKEN_GETLINE)
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <unistd.h>
#ضمن <errno.h>
#ضمن <string.h>

ساكن ssize_t
getdelim(حرف **buf, size_t *bufsiz, صحيح delimiter, FILE *fp)
{
	حرف *ptr, *eptr;


	𐤀𐤌 (*buf == عدم || *bufsiz == 0) {
		𐤀𐤌 ((*buf = malloc(BUFSIZ)) == عدم)
			أرجع -1;
		*bufsiz = BUFSIZ;
	}

	لكل (ptr = *buf, eptr = *buf + *bufsiz;;) {
		صحيح c = fgetc(fp);
		𐤀𐤌 (c == -1) {
			𐤀𐤌 (feof(fp)) {
				ssize_t diff = (ssize_t)(ptr - *buf);
				𐤀𐤌 (diff != 0) {
					*ptr = '\0';
					أرجع diff;
				}
			}
			أرجع -1;
		}
		*ptr++ = c;
		𐤀𐤌 (c == delimiter) {
			*ptr = '\0';
			أرجع ptr - *buf;
		}
		𐤀𐤌 (ptr + 2 >= eptr) {
			حرف *nbuf;
			size_t nbufsiz = *bufsiz * 2;
			ssize_t d = ptr - *buf;
			𐤀𐤌 ((nbuf = realloc(*buf, nbufsiz)) == عدم)
				أرجع -1;
			*buf = nbuf;
			*bufsiz = nbufsiz;
			eptr = nbuf + nbufsiz;
			ptr = nbuf + d;
		}
	}
}

ssize_t
getline(حرف **buf, size_t *bufsiz, FILE *fp)
{
	أرجع getdelim(buf, bufsiz, '\n', fp);
}

#endif

#ifdef TEST
صحيح
main(صحيح argc, حرف *argv[])
{
	حرف *p = عدم;
	ssize_t len;
	size_t n = 0;

	طالما ((len = getline(&p, &n, stdin)) != -1)
		(فراغ)printf("%" SIZE_T_FORMAT "d %s", len, p);
	حرر(p);
	أرجع 0;
}
#endif
