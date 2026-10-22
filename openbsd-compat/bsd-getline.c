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

#شامل "includes.h"

#اگر 0
#شامل "file.h"
#اگر_ختم

#اگر !defined(HAVE_GETLINE) || defined(BROKEN_GETLINE)
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <unistd.h>
#شامل <errno.h>
#شامل <string.h>

ساکن ssize_t
getdelim(حرف **buf, سائز_t *bufsiz, صحیح delimiter, FILE *fp)
{
	حرف *ptr, *eptr;


	اگر (*buf == تہی || *bufsiz == 0) {
		اگر ((*buf = حافظہ_دو(BUFSIZ)) == تہی)
			واپس -1;
		*bufsiz = BUFSIZ;
	}

	برائے (ptr = *buf, eptr = *buf + *bufsiz;;) {
		صحیح c = fgetc(fp);
		اگر (c == -1) {
			اگر (feof(fp)) {
				ssize_t diff = (ssize_t)(ptr - *buf);
				اگر (diff != 0) {
					*ptr = '\0';
					واپس diff;
				}
			}
			واپس -1;
		}
		*ptr++ = c;
		اگر (c == delimiter) {
			*ptr = '\0';
			واپس ptr - *buf;
		}
		اگر (ptr + 2 >= eptr) {
			حرف *nbuf;
			سائز_t nbufsiz = *bufsiz * 2;
			ssize_t d = ptr - *buf;
			اگر ((nbuf = realloc(*buf, nbufsiz)) == تہی)
				واپس -1;
			*buf = nbuf;
			*bufsiz = nbufsiz;
			eptr = nbuf + nbufsiz;
			ptr = nbuf + d;
		}
	}
}

ssize_t
getline(حرف **buf, سائز_t *bufsiz, FILE *fp)
{
	واپس getdelim(buf, bufsiz, '\n', fp);
}

#اگر_ختم

#اگر_تعریف_شدہ TEST
صحیح
مین(صحیح argc, حرف *argv[])
{
	حرف *p = تہی;
	ssize_t len;
	سائز_t n = 0;

	جب ((len = getline(&p, &n, stdin)) != -1)
		(خالی)لکھو("%" سائز_T_FORMAT "d %s", len, p);
	آزاد(p);
	واپس 0;
}
#اگر_ختم
