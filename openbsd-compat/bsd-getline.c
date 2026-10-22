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

#यदि 0
#अन्तर्भाव "file.h"
#endif

#यदि !defined(HAVE_GETLINE) || defined(BROKEN_GETLINE)
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <string.h>

स्थिर ssize_t
getdelim(वर्ण **buf, माप_प्रकार *bufsiz, पूर्णाङ्क delimiter, खाता *fp)
{
	वर्ण *ptr, *eptr;


	यदि (*buf == रिक्त || *bufsiz == 0) {
		यदि ((*buf = दो_स्मृति(बफ_मान)) == रिक्त)
			फर्काऊ -1;
		*bufsiz = बफ_मान;
	}

	लागि (ptr = *buf, eptr = *buf + *bufsiz;;) {
		पूर्णाङ्क c = ख_अक्षर_लो(fp);
		यदि (c == -1) {
			यदि (ख_पूर्ण(fp)) {
				ssize_t diff = (ssize_t)(ptr - *buf);
				यदि (diff != 0) {
					*ptr = '\0';
					फर्काऊ diff;
				}
			}
			फर्काऊ -1;
		}
		*ptr++ = c;
		यदि (c == delimiter) {
			*ptr = '\0';
			फर्काऊ ptr - *buf;
		}
		यदि (ptr + 2 >= eptr) {
			वर्ण *nbuf;
			माप_प्रकार nbufsiz = *bufsiz * 2;
			ssize_t d = ptr - *buf;
			यदि ((nbuf = पुनः_स्मृति(*buf, nbufsiz)) == रिक्त)
				फर्काऊ -1;
			*buf = nbuf;
			*bufsiz = nbufsiz;
			eptr = nbuf + nbufsiz;
			ptr = nbuf + d;
		}
	}
}

ssize_t
getline(वर्ण **buf, माप_प्रकार *bufsiz, खाता *fp)
{
	फर्काऊ getdelim(buf, bufsiz, '\n', fp);
}

#endif

#ifdef TEST
पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण *argv[])
{
	वर्ण *p = रिक्त;
	ssize_t len;
	माप_प्रकार n = 0;

	जबसम्म ((len = getline(&p, &n, मानक_निवेश)) != -1)
		(शून्य)म_लिखो("%" SIZE_T_FORMAT "d %s", len, p);
	मुक्त(p);
	फर्काऊ 0;
}
#endif
