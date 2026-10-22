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

#만약 0
#include "file.h"
#endif

#만약 !defined(HAVE_GETLINE) || defined(BROKEN_GETLINE)
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

static ssize_t
getdelim(char **buf, size_t *bufsiz, 정수 delimiter, FILE *fp)
{
	char *ptr, *eptr;


	만약 (*buf == NULL || *bufsiz == 0) {
		만약 ((*buf = malloc(BUFSIZ)) == NULL)
			반환 -1;
		*bufsiz = BUFSIZ;
	}

	위해 (ptr = *buf, eptr = *buf + *bufsiz;;) {
		정수 c = fgetc(fp);
		만약 (c == -1) {
			만약 (feof(fp)) {
				ssize_t diff = (ssize_t)(ptr - *buf);
				만약 (diff != 0) {
					*ptr = '\0';
					반환 diff;
				}
			}
			반환 -1;
		}
		*ptr++ = c;
		만약 (c == delimiter) {
			*ptr = '\0';
			반환 ptr - *buf;
		}
		만약 (ptr + 2 >= eptr) {
			char *nbuf;
			size_t nbufsiz = *bufsiz * 2;
			ssize_t d = ptr - *buf;
			만약 ((nbuf = realloc(*buf, nbufsiz)) == NULL)
				반환 -1;
			*buf = nbuf;
			*bufsiz = nbufsiz;
			eptr = nbuf + nbufsiz;
			ptr = nbuf + d;
		}
	}
}

ssize_t
getline(char **buf, size_t *bufsiz, FILE *fp)
{
	반환 getdelim(buf, bufsiz, '\n', fp);
}

#endif

#ifdef TEST
정수
main(정수 argc, char *argv[])
{
	char *p = NULL;
	ssize_t len;
	size_t n = 0;

	동안 ((len = getline(&p, &n, stdin)) != -1)
		(void)printf("%" SIZE_T_FORMAT "d %s", len, p);
	free(p);
	반환 0;
}
#endif
