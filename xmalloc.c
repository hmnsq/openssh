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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "log.h"

#যদি defined(__OpenBSD__)
ধ্রুৱ ৱর্ণ * ধ্রুৱ malloc_options = "S";
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
	ঘূৰাই ptr;
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
	ঘূৰাই ptr;
}

শূন্য *
xreallocarray(শূন্য *ptr, size_t nmemb, size_t size)
{
	শূন্য *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, size);
	যদি (new_ptr == রিক্ত)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	ঘূৰাই new_ptr;
}

শূন্য *
xrecallocarray(শূন্য *ptr, size_t onmemb, size_t nmemb, size_t size)
{
	শূন্য *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, size);
	যদি (new_ptr == রিক্ত)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	ঘূৰাই new_ptr;
}

ৱর্ণ *
xstrdup(ধ্রুৱ ৱর্ণ *str)
{
	size_t len;
	ৱর্ণ *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	ঘূৰাই memcpy(cp, str, len);
}

পূর্ণাঙ্ক
xvasprintf(ৱর্ণ **ret, ধ্রুৱ ৱর্ণ *fmt, va_list ap)
{
	পূর্ণাঙ্ক i;

	i = vasprintf(ret, fmt, ap);
	যদি (i < 0 || *ret == রিক্ত)
		fatal("xvasprintf: could not allocate memory");
	ঘূৰাই i;
}

পূর্ণাঙ্ক
xasprintf(ৱর্ণ **ret, ধ্রুৱ ৱর্ণ *fmt, ...)
{
	va_list ap;
	পূর্ণাঙ্ক i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	ঘূৰাই i;
}
