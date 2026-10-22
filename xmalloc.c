/* $OpenBSD: xmalloc.c,v 1.38 2025/05/23 00:40:45 deraadt Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Versions of malloc and friends that check their results, and never return
 * failure (they call fatal if they encounter an error).
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "log.h"

#ఒకవేళ defined(__OpenBSD__)
స్థిరరాశి అక్షరం * స్థిరరాశి malloc_options = "S";
#అయితే_ముగింపు /* __OpenBSD__ */

శూన్య *
xmalloc(కొలత_t కొలత)
{
	శూన్య *ptr;

	ఒకవేళ (కొలత == 0)
		fatal("xmalloc: zero size");
	ptr = జ్ఞాపకం_ఇవ్వు(కొలత);
	ఒకవేళ (ptr == ఖాళీ)
		fatal("xmalloc: out of memory (allocating %zu bytes)", కొలత);
	తిరిగి ptr;
}

శూన్య *
xcalloc(కొలత_t nmemb, కొలత_t కొలత)
{
	శూన్య *ptr;

	ఒకవేళ (కొలత == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	ఒకవేళ (SIZE_MAX / nmemb < కొలత)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = సున్నా_జ్ఞాపకం_ఇవ్వు(nmemb, కొలత);
	ఒకవేళ (ptr == ఖాళీ)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    కొలత * nmemb);
	తిరిగి ptr;
}

శూన్య *
xreallocarray(శూన్య *ptr, కొలత_t nmemb, కొలత_t కొలత)
{
	శూన్య *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, కొలత);
	ఒకవేళ (new_ptr == ఖాళీ)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, కొలత);
	తిరిగి new_ptr;
}

శూన్య *
xrecallocarray(శూన్య *ptr, కొలత_t onmemb, కొలత_t nmemb, కొలత_t కొలత)
{
	శూన్య *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, కొలత);
	ఒకవేళ (new_ptr == ఖాళీ)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, కొలత);
	తిరిగి new_ptr;
}

అక్షరం *
xstrdup(స్థిరరాశి అక్షరం *str)
{
	కొలత_t len;
	అక్షరం *cp;

	len = అక్షరశ్రేణి_పొడవు(str) + 1;
	cp = xmalloc(len);
	తిరిగి జ్ఞాపకం_నకలు(cp, str, len);
}

పూర్ణాంకం
xvasprintf(అక్షరం **ret, స్థిరరాశి అక్షరం *fmt, va_list ap)
{
	పూర్ణాంకం i;

	i = vasprintf(ret, fmt, ap);
	ఒకవేళ (i < 0 || *ret == ఖాళీ)
		fatal("xvasprintf: could not allocate memory");
	తిరిగి i;
}

పూర్ణాంకం
xasprintf(అక్షరం **ret, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list ap;
	పూర్ణాంకం i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	తిరిగి i;
}
