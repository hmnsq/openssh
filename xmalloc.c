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
ধ্রুবক অক্ষর * ধ্রুবক malloc_options = "S";
#endif /* __OpenBSD__ */

শূন্য *
xmalloc(আকার_t আকার_2)
{
	শূন্য *ptr;

	যদি (আকার_2 == 0)
		fatal("xmalloc: zero size");
	ptr = malloc(আকার_2);
	যদি (ptr == ফাঁকা)
		fatal("xmalloc: out of memory (allocating %zu bytes)", আকার_2);
	ফেরত ptr;
}

শূন্য *
xcalloc(আকার_t nmemb, আকার_t আকার_2)
{
	শূন্য *ptr;

	যদি (আকার_2 == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	যদি (SIZE_MAX / nmemb < আকার_2)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = calloc(nmemb, আকার_2);
	যদি (ptr == ফাঁকা)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    আকার_2 * nmemb);
	ফেরত ptr;
}

শূন্য *
xreallocarray(শূন্য *ptr, আকার_t nmemb, আকার_t আকার_2)
{
	শূন্য *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, আকার_2);
	যদি (new_ptr == ফাঁকা)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, আকার_2);
	ফেরত new_ptr;
}

শূন্য *
xrecallocarray(শূন্য *ptr, আকার_t onmemb, আকার_t nmemb, আকার_t আকার_2)
{
	শূন্য *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, আকার_2);
	যদি (new_ptr == ফাঁকা)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, আকার_2);
	ফেরত new_ptr;
}

অক্ষর *
xstrdup(ধ্রুবক অক্ষর *str)
{
	আকার_t len;
	অক্ষর *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	ফেরত memcpy(cp, str, len);
}

পূর্ণসংখ্যা
xvasprintf(অক্ষর **ret, ধ্রুবক অক্ষর *fmt, va_list ap)
{
	পূর্ণসংখ্যা i;

	i = vasprintf(ret, fmt, ap);
	যদি (i < 0 || *ret == ফাঁকা)
		fatal("xvasprintf: could not allocate memory");
	ফেরত i;
}

পূর্ণসংখ্যা
xasprintf(অক্ষর **ret, ধ্রুবক অক্ষর *fmt, ...)
{
	va_list ap;
	পূর্ণসংখ্যা i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	ফেরত i;
}
