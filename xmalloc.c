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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

#ଯଦି defined(__OpenBSD__)
ଅଚଳ ଅକ୍ଷର * ଅଚଳ malloc_options = "S";
#endif /* __OpenBSD__ */

ଶୂନ୍ୟ *
xmalloc(size_t size)
{
	ଶୂନ୍ୟ *ptr;

	ଯଦି (size == 0)
		fatal("xmalloc: zero size");
	ptr = malloc(size);
	ଯଦି (ptr == ଖାଲି)
		fatal("xmalloc: out of memory (allocating %zu bytes)", size);
	ଫେରନ୍ତୁ ptr;
}

ଶୂନ୍ୟ *
xcalloc(size_t nmemb, size_t size)
{
	ଶୂନ୍ୟ *ptr;

	ଯଦି (size == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	ଯଦି (SIZE_MAX / nmemb < size)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = calloc(nmemb, size);
	ଯଦି (ptr == ଖାଲି)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    size * nmemb);
	ଫେରନ୍ତୁ ptr;
}

ଶୂନ୍ୟ *
xreallocarray(ଶୂନ୍ୟ *ptr, size_t nmemb, size_t size)
{
	ଶୂନ୍ୟ *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, size);
	ଯଦି (new_ptr == ଖାଲି)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	ଫେରନ୍ତୁ new_ptr;
}

ଶୂନ୍ୟ *
xrecallocarray(ଶୂନ୍ୟ *ptr, size_t onmemb, size_t nmemb, size_t size)
{
	ଶୂନ୍ୟ *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, size);
	ଯଦି (new_ptr == ଖାଲି)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	ଫେରନ୍ତୁ new_ptr;
}

ଅକ୍ଷର *
xstrdup(ଅଚଳ ଅକ୍ଷର *str)
{
	size_t len;
	ଅକ୍ଷର *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	ଫେରନ୍ତୁ memcpy(cp, str, len);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
xvasprintf(ଅକ୍ଷର **ret, ଅଚଳ ଅକ୍ଷର *fmt, va_list ap)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	i = vasprintf(ret, fmt, ap);
	ଯଦି (i < 0 || *ret == ଖାଲି)
		fatal("xvasprintf: could not allocate memory");
	ଫେରନ୍ତୁ i;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
xasprintf(ଅକ୍ଷର **ret, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list ap;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	ଫେରନ୍ତୁ i;
}
