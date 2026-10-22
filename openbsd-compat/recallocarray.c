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

#అన్తర్భావ "includes.h"
#నిర్వచితం_కాకపోతే HAVE_RECALLOCARRAY

#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#నిర్వచించు MUL_NO_అధికప్రవాహం ((కొలత_t)1 << (పరిమాణం(కొలత_t) * 4))

శూన్య *
recallocarray(శూన్య *ptr, కొలత_t oldnmemb, కొలత_t newnmemb, కొలత_t కొలత)
{
	కొలత_t oldsize, newsize;
	శూన్య *newptr;

	ఒకవేళ (ptr == ఖాళీ)
		తిరిగి సున్నా_జ్ఞాపకం_ఇవ్వు(newnmemb, కొలత);

	ఒకవేళ ((newnmemb >= MUL_NO_అధికప్రవాహం || కొలత >= MUL_NO_అధికప్రవాహం) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < కొలత) {
		errno = ENOMEM;
		తిరిగి ఖాళీ;
	}
	newsize = newnmemb * కొలత;

	ఒకవేళ ((oldnmemb >= MUL_NO_అధికప్రవాహం || కొలత >= MUL_NO_అధికప్రవాహం) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < కొలత) {
		errno = EINVAL;
		తిరిగి ఖాళీ;
	}
	oldsize = oldnmemb * కొలత;
	
	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	ఒకవేళ (newsize <= oldsize) {
		కొలత_t d = oldsize - newsize;

		ఒకవేళ (d < oldsize / 2 && d < (కొలత_t)getpagesize()) {
			memset((అక్షరం *)ptr + newsize, 0, d);
			తిరిగి ptr;
		}
	}

	newptr = జ్ఞాపకం_ఇవ్వు(newsize);
	ఒకవేళ (newptr == ఖాళీ)
		తిరిగి ఖాళీ;

	ఒకవేళ (newsize > oldsize) {
		జ్ఞాపకం_నకలు(newptr, ptr, oldsize);
		memset((అక్షరం *)newptr + oldsize, 0, newsize - oldsize);
	} లేకపోతే
		జ్ఞాపకం_నకలు(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	విడుదల(ptr);

	తిరిగి newptr;
}
/* DEF_WEAK(recallocarray); */

#అయితే_ముగింపు /* HAVE_RECALLOCARRAY */
