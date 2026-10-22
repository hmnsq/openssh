/*	$OpenBSD: recallocarray.c,v 1.1 2017/03/06 18:44:21 otto Exp $	*/
/*
 * Copyright (c) 2008, 2017 Otto Moerbeek <otto@drijf.net>
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

/* OPENBSD ORIGINAL: lib/libc/stdlib/recallocarray.c */

#شامل "includes.h"
#اگر_غیر_تعریف_شدہ HAVE_RECALLOCARRAY

#شامل <errno.h>
#شامل <stdlib.h>
#شامل <stdint.h>
#شامل <string.h>
#شامل <unistd.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#تعریف_کرو MUL_NO_حد_سے_تجاوز ((سائز_t)1 << (حجم(سائز_t) * 4))

خالی *
recallocarray(خالی *ptr, سائز_t oldnmemb, سائز_t newnmemb, سائز_t سائز)
{
	سائز_t oldsize, newsize;
	خالی *newptr;

	اگر (ptr == تہی)
		واپس صفر_حافظہ_دو(newnmemb, سائز);

	اگر ((newnmemb >= MUL_NO_حد_سے_تجاوز || سائز >= MUL_NO_حد_سے_تجاوز) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < سائز) {
		errno = ENOMEM;
		واپس تہی;
	}
	newsize = newnmemb * سائز;

	اگر ((oldnmemb >= MUL_NO_حد_سے_تجاوز || سائز >= MUL_NO_حد_سے_تجاوز) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < سائز) {
		errno = EINVAL;
		واپس تہی;
	}
	oldsize = oldnmemb * سائز;
	
	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	اگر (newsize <= oldsize) {
		سائز_t d = oldsize - newsize;

		اگر (d < oldsize / 2 && d < (سائز_t)getpagesize()) {
			memset((حرف *)ptr + newsize, 0, d);
			واپس ptr;
		}
	}

	newptr = حافظہ_دو(newsize);
	اگر (newptr == تہی)
		واپس تہی;

	اگر (newsize > oldsize) {
		حافظہ_نقل(newptr, ptr, oldsize);
		memset((حرف *)newptr + oldsize, 0, newsize - oldsize);
	} ورنہ
		حافظہ_نقل(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	آزاد(ptr);

	واپس newptr;
}
/* DEF_WEAK(recallocarray); */

#اگر_ختم /* HAVE_RECALLOCARRAY */
