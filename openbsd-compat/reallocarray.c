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

#अन्तर्भाव "includes.h"
#यदि_अपरिभाषितम् HAVE_REALLOCARRAY

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#परिभाषय MUL_NO_अतिप्रवाहः	((आकार_t)1 << (परिमाण(आकार_t) * 4))

शून्य *
reallocarray(शून्य *optr, आकार_t nmemb, आकार_t आकार)
{
	यदि ((nmemb >= MUL_NO_अतिप्रवाहः || आकार >= MUL_NO_अतिप्रवाहः) &&
	    nmemb > 0 && SIZE_MAX / nmemb < आकार) {
		errno = ENOMEM;
		प्रत्यागम रिक्त;
	}
	प्रत्यागम realloc(optr, आकार * nmemb);
}
#यदि_अन्तः /* HAVE_REALLOCARRAY */
