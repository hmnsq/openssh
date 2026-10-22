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

#شامل "includes.h"

#شامل <stdarg.h>
#شامل <stdint.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "xmalloc.h"
#شامل "log.h"

#اگر defined(__OpenBSD__)
ثابت نویسه * ثابت malloc_options = "S";
#endif /* __OpenBSD__ */

تهی *
xmalloc(size_t size)
{
	تهی *ptr;

	اگر (size == 0)
		fatal("xmalloc: zero size");
	ptr = malloc(size);
	اگر (ptr == پوچ)
		fatal("xmalloc: out of memory (allocating %zu bytes)", size);
	بازگشت ptr;
}

تهی *
xcalloc(size_t nmemb, size_t size)
{
	تهی *ptr;

	اگر (size == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	اگر (SIZE_MAX / nmemb < size)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = calloc(nmemb, size);
	اگر (ptr == پوچ)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    size * nmemb);
	بازگشت ptr;
}

تهی *
xreallocarray(تهی *ptr, size_t nmemb, size_t size)
{
	تهی *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, size);
	اگر (new_ptr == پوچ)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	بازگشت new_ptr;
}

تهی *
xrecallocarray(تهی *ptr, size_t onmemb, size_t nmemb, size_t size)
{
	تهی *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, size);
	اگر (new_ptr == پوچ)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	بازگشت new_ptr;
}

نویسه *
xstrdup(ثابت نویسه *str)
{
	size_t len;
	نویسه *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	بازگشت memcpy(cp, str, len);
}

صحیح
xvasprintf(نویسه **ret, ثابت نویسه *fmt, va_list ap)
{
	صحیح i;

	i = vasprintf(ret, fmt, ap);
	اگر (i < 0 || *ret == پوچ)
		fatal("xvasprintf: could not allocate memory");
	بازگشت i;
}

صحیح
xasprintf(نویسه **ret, ثابت نویسه *fmt, ...)
{
	va_list ap;
	صحیح i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	بازگشت i;
}
