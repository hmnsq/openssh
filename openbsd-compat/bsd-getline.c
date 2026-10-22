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

#include "includes.h"

#ᱡᱩᱫᱤ 0
#include "file.h"
#endif

#ᱡᱩᱫᱤ !defined(HAVE_GETLINE) || defined(BROKEN_GETLINE)
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

static ssize_t
getdelim(var_na **buf, size_t *bufsiz, puur_naa_nka delimiter, FILE *fp)
{
	var_na *ptr, *eptr;


	ᱡᱩᱫᱤ (*buf == NULL || *bufsiz == 0) {
		ᱡᱩᱫᱤ ((*buf = malloc(BUFSIZ)) == NULL)
			ᱨᱩᱣᱟᱹᱲ -1;
		*bufsiz = BUFSIZ;
	}

	for (ptr = *buf, eptr = *buf + *bufsiz;;) {
		puur_naa_nka c = fgetc(fp);
		ᱡᱩᱫᱤ (c == -1) {
			ᱡᱩᱫᱤ (feof(fp)) {
				ssize_t diff = (ssize_t)(ptr - *buf);
				ᱡᱩᱫᱤ (diff != 0) {
					*ptr = '\0';
					ᱨᱩᱣᱟᱹᱲ diff;
				}
			}
			ᱨᱩᱣᱟᱹᱲ -1;
		}
		*ptr++ = c;
		ᱡᱩᱫᱤ (c == delimiter) {
			*ptr = '\0';
			ᱨᱩᱣᱟᱹᱲ ptr - *buf;
		}
		ᱡᱩᱫᱤ (ptr + 2 >= eptr) {
			var_na *nbuf;
			size_t nbufsiz = *bufsiz * 2;
			ssize_t d = ptr - *buf;
			ᱡᱩᱫᱤ ((nbuf = realloc(*buf, nbufsiz)) == NULL)
				ᱨᱩᱣᱟᱹᱲ -1;
			*buf = nbuf;
			*bufsiz = nbufsiz;
			eptr = nbuf + nbufsiz;
			ptr = nbuf + d;
		}
	}
}

ssize_t
getline(var_na **buf, size_t *bufsiz, FILE *fp)
{
	ᱨᱩᱣᱟᱹᱲ getdelim(buf, bufsiz, '\n', fp);
}

#endif

#ifdef TEST
puur_naa_nka
main(puur_naa_nka argc, var_na *argv[])
{
	var_na *p = NULL;
	ssize_t len;
	size_t n = 0;

	ᱡᱚᱠᱷᱚᱱ ((len = getline(&p, &n, stdin)) != -1)
		(void)printf("%" SIZE_T_FORMAT "d %s", len, p);
	free(p);
	ᱨᱩᱣᱟᱹᱲ 0;
}
#endif
