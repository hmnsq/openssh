/*	$OpenBSD: reallocarray.c,v 1.2 2014/12/08 03:45:00 bcook Exp $	*/
/*
 * Copyright (c) 2008 Otto Moerbeek <otto@drijf.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* OPENBSD ORIGINAL: lib/libc/stdlib/reallocarray.c */

#समावेश "includes.h"
#अगर_अघोषित HAVE_REALLOCARRAY

#समावेश <sys/types.h>
#समावेश <errno.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#घोषणा MUL_NO_OVERFLOW	((माप_प्रकार)1 << (माप(माप_प्रकार) * 4))

व्योम *
reallocarray(व्योम *optr, माप_प्रकार nmemb, माप_प्रकार आकार)
{
	अगर ((nmemb >= MUL_NO_OVERFLOW || आकार >= MUL_NO_OVERFLOW) &&
	    nmemb > 0 && SIZE_MAX / nmemb < आकार) {
		त्रुटि_सं = ENOMEM;
		वापस शून्य;
	}
	वापस पुनः_स्मृति(optr, आकार * nmemb);
}
#पूर्ण_अगर /* HAVE_REALLOCARRAY */
