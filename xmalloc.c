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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "log.h"

#જો defined(__OpenBSD__)
અચલ અક્ષર * અચલ malloc_options = "S";
#endif /* __OpenBSD__ */

શૂન્ય *
xmalloc(size_t size)
{
	શૂન્ય *ptr;

	જો (size == 0)
		fatal("xmalloc: zero size");
	ptr = malloc(size);
	જો (ptr == ખાલી)
		fatal("xmalloc: out of memory (allocating %zu bytes)", size);
	પાછા ptr;
}

શૂન્ય *
xcalloc(size_t nmemb, size_t size)
{
	શૂન્ય *ptr;

	જો (size == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	જો (SIZE_MAX / nmemb < size)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = calloc(nmemb, size);
	જો (ptr == ખાલી)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    size * nmemb);
	પાછા ptr;
}

શૂન્ય *
xreallocarray(શૂન્ય *ptr, size_t nmemb, size_t size)
{
	શૂન્ય *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, size);
	જો (new_ptr == ખાલી)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	પાછા new_ptr;
}

શૂન્ય *
xrecallocarray(શૂન્ય *ptr, size_t onmemb, size_t nmemb, size_t size)
{
	શૂન્ય *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, size);
	જો (new_ptr == ખાલી)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	પાછા new_ptr;
}

અક્ષર *
xstrdup(અચલ અક્ષર *str)
{
	size_t len;
	અક્ષર *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	પાછા memcpy(cp, str, len);
}

પૂર્ણાંક
xvasprintf(અક્ષર **ret, અચલ અક્ષર *fmt, va_list ap)
{
	પૂર્ણાંક i;

	i = vasprintf(ret, fmt, ap);
	જો (i < 0 || *ret == ખાલી)
		fatal("xvasprintf: could not allocate memory");
	પાછા i;
}

પૂર્ણાંક
xasprintf(અક્ષર **ret, અચલ અક્ષર *fmt, ...)
{
	va_list ap;
	પૂર્ણાંક i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	પાછા i;
}
