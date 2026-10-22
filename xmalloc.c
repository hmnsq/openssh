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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "log.h"

#எனில் defined(__OpenBSD__)
மாறிலி எழுத்து * மாறிலி malloc_options = "S";
#endif /* __OpenBSD__ */

வெறுமை *
xmalloc(size_t size)
{
	வெறுமை *ptr;

	எனில் (size == 0)
		fatal("xmalloc: zero size");
	ptr = malloc(size);
	எனில் (ptr == வெற்று)
		fatal("xmalloc: out of memory (allocating %zu bytes)", size);
	திரும்பு ptr;
}

வெறுமை *
xcalloc(size_t nmemb, size_t size)
{
	வெறுமை *ptr;

	எனில் (size == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	எனில் (SIZE_MAX / nmemb < size)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = calloc(nmemb, size);
	எனில் (ptr == வெற்று)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    size * nmemb);
	திரும்பு ptr;
}

வெறுமை *
xreallocarray(வெறுமை *ptr, size_t nmemb, size_t size)
{
	வெறுமை *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, size);
	எனில் (new_ptr == வெற்று)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	திரும்பு new_ptr;
}

வெறுமை *
xrecallocarray(வெறுமை *ptr, size_t onmemb, size_t nmemb, size_t size)
{
	வெறுமை *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, size);
	எனில் (new_ptr == வெற்று)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	திரும்பு new_ptr;
}

எழுத்து *
xstrdup(மாறிலி எழுத்து *str)
{
	size_t len;
	எழுத்து *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	திரும்பு memcpy(cp, str, len);
}

முழு
xvasprintf(எழுத்து **ret, மாறிலி எழுத்து *fmt, va_list ap)
{
	முழு i;

	i = vasprintf(ret, fmt, ap);
	எனில் (i < 0 || *ret == வெற்று)
		fatal("xvasprintf: could not allocate memory");
	திரும்பு i;
}

முழு
xasprintf(எழுத்து **ret, மாறிலி எழுத்து *fmt, ...)
{
	va_list ap;
	முழு i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	திரும்பு i;
}
