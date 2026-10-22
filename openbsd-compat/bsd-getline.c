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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ 0
#ਅਨ੍ਤਰ੍ਭਾਵ "file.h"
#ਜੇ_ਅੰਤ

#ਜੇ !defined(HAVE_GETLINE) || defined(BROKEN_GETLINE)
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

ਸਥਿਰ ssize_t
getdelim(ਅੱਖਰ **buf, ਮਾਪ_t *bufsiz, ਪੂਰਨ delimiter, FILE *fp)
{
	ਅੱਖਰ *ptr, *eptr;


	ਜੇ (*buf == ਨਿਰਾ || *bufsiz == 0) {
		ਜੇ ((*buf = ਸਮ੍ਰਿਤੀ_ਦਿਓ(BUFSIZ)) == ਨਿਰਾ)
			ਵਾਪਸ -1;
		*bufsiz = BUFSIZ;
	}

	ਲਈ (ptr = *buf, eptr = *buf + *bufsiz;;) {
		ਪੂਰਨ c = fgetc(fp);
		ਜੇ (c == -1) {
			ਜੇ (feof(fp)) {
				ssize_t diff = (ssize_t)(ptr - *buf);
				ਜੇ (diff != 0) {
					*ptr = '\0';
					ਵਾਪਸ diff;
				}
			}
			ਵਾਪਸ -1;
		}
		*ptr++ = c;
		ਜੇ (c == delimiter) {
			*ptr = '\0';
			ਵਾਪਸ ptr - *buf;
		}
		ਜੇ (ptr + 2 >= eptr) {
			ਅੱਖਰ *nbuf;
			ਮਾਪ_t nbufsiz = *bufsiz * 2;
			ssize_t d = ptr - *buf;
			ਜੇ ((nbuf = realloc(*buf, nbufsiz)) == ਨਿਰਾ)
				ਵਾਪਸ -1;
			*buf = nbuf;
			*bufsiz = nbufsiz;
			eptr = nbuf + nbufsiz;
			ptr = nbuf + d;
		}
	}
}

ssize_t
getline(ਅੱਖਰ **buf, ਮਾਪ_t *bufsiz, FILE *fp)
{
	ਵਾਪਸ getdelim(buf, bufsiz, '\n', fp);
}

#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ TEST
ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ *argv[])
{
	ਅੱਖਰ *p = ਨਿਰਾ;
	ssize_t len;
	ਮਾਪ_t n = 0;

	ਜਦੋਂ ((len = getline(&p, &n, stdin)) != -1)
		(ਖਾਲੀ)ਲਿਖੋ("%" ਮਾਪ_T_FORMAT "d %s", len, p);
	ਮੁਕਤ(p);
	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ
