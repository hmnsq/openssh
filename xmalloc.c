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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "log.h"

#যদি defined(__OpenBSD__)
ধ্রুব বর্ণ * ধ্রুব malloc_options = "S";
#endif /* __OpenBSD__ */

শূন্য *
xmalloc(size_t size)
{
	শূন্য *ptr;

	যদি (size == 0)
		fatal("xmalloc: zero size");
	ptr = malloc(size);
	যদি (ptr == রিক্ত)
		fatal("xmalloc: out of memory (allocating %zu bytes)", size);
	প্রত্যাগম ptr;
}

শূন্য *
xcalloc(size_t nmemb, size_t size)
{
	শূন্য *ptr;

	যদি (size == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	যদি (SIZE_MAX / nmemb < size)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = calloc(nmemb, size);
	যদি (ptr == রিক্ত)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    size * nmemb);
	প্রত্যাগম ptr;
}

শূন্য *
xreallocarray(শূন্য *ptr, size_t nmemb, size_t size)
{
	শূন্য *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, size);
	যদি (new_ptr == রিক্ত)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	প্রত্যাগম new_ptr;
}

শূন্য *
xrecallocarray(শূন্য *ptr, size_t onmemb, size_t nmemb, size_t size)
{
	শূন্য *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, size);
	যদি (new_ptr == রিক্ত)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	প্রত্যাগম new_ptr;
}

বর্ণ *
xstrdup(ধ্রুব বর্ণ *str)
{
	size_t len;
	বর্ণ *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	প্রত্যাগম memcpy(cp, str, len);
}

পূর্ণাঙ্ক
xvasprintf(বর্ণ **ret, ধ্রুব বর্ণ *fmt, va_list ap)
{
	পূর্ণাঙ্ক i;

	i = vasprintf(ret, fmt, ap);
	যদি (i < 0 || *ret == রিক্ত)
		fatal("xvasprintf: could not allocate memory");
	প্রত্যাগম i;
}

পূর্ণাঙ্ক
xasprintf(বর্ণ **ret, ধ্রুব বর্ণ *fmt, ...)
{
	va_list ap;
	পূর্ণাঙ্ক i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	প্রত্যাগম i;
}
