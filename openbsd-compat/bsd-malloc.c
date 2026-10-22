/*
 * Copyright (c) 2017 Darren Tucker (dtucker at zip com au).
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

#అన్తర్భావ "config.h"
#నిర్వచనం_రద్దు జ్ఞాపకం_ఇవ్వు
#నిర్వచనం_రద్దు సున్నా_జ్ఞాపకం_ఇవ్వు
#నిర్వచనం_రద్దు realloc

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdlib.h>

#ఒకవేళ defined(HAVE_MALLOC) && HAVE_MALLOC == 0
శూన్య *
rpl_malloc(కొలత_t కొలత)
{
	ఒకవేళ (కొలత == 0)
		కొలత = 1;
	తిరిగి జ్ఞాపకం_ఇవ్వు(కొలత);
}
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_CALLOC) && HAVE_CALLOC == 0
శూన్య *
rpl_calloc(కొలత_t nmemb, కొలత_t కొలత)
{
	ఒకవేళ (nmemb == 0)
		nmemb = 1;
	ఒకవేళ (కొలత == 0)
		కొలత = 1;
	తిరిగి సున్నా_జ్ఞాపకం_ఇవ్వు(nmemb, కొలత);
}
#అయితే_ముగింపు

#ఒకవేళ defined (HAVE_REALLOC) && HAVE_REALLOC == 0
శూన్య *
rpl_realloc(శూన్య *ptr, కొలత_t కొలత)
{
	ఒకవేళ (కొలత == 0)
		కొలత = 1;
	ఒకవేళ (ptr == 0)
		తిరిగి జ్ఞాపకం_ఇవ్వు(కొలత);
	తిరిగి realloc(ptr, కొలత);
}
#అయితే_ముగింపు
