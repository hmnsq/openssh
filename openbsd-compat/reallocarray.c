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

#అన్తర్భావ "includes.h"
#నిర్వచితం_కాకపోతే HAVE_REALLOCARRAY

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#నిర్వచించు MUL_NO_అధికప్రవాహం	((కొలత_t)1 << (పరిమాణం(కొలత_t) * 4))

శూన్య *
reallocarray(శూన్య *optr, కొలత_t nmemb, కొలత_t కొలత)
{
	ఒకవేళ ((nmemb >= MUL_NO_అధికప్రవాహం || కొలత >= MUL_NO_అధికప్రవాహం) &&
	    nmemb > 0 && SIZE_MAX / nmemb < కొలత) {
		errno = ENOMEM;
		తిరిగి ఖాళీ;
	}
	తిరిగి realloc(optr, కొలత * nmemb);
}
#అయితే_ముగింపు /* HAVE_REALLOCARRAY */
