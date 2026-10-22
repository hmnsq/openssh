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

#include "includes.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xmalloc.h"
#include "log.h"

#ако defined(__OpenBSD__)
const char * const malloc_options = "S";
#endif /* __OpenBSD__ */

void *
xmalloc(size_t size)
{
	void *ptr;

	ако (size == 0)
		fatal("xmalloc: zero size");
	ptr = malloc(size);
	ако (ptr == NULL)
		fatal("xmalloc: out of memory (allocating %zu bytes)", size);
	врати ptr;
}

void *
xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	ако (size == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	ако (SIZE_MAX / nmemb < size)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = calloc(nmemb, size);
	ако (ptr == NULL)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    size * nmemb);
	врати ptr;
}

void *
xreallocarray(void *ptr, size_t nmemb, size_t size)
{
	void *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, size);
	ако (new_ptr == NULL)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	врати new_ptr;
}

void *
xrecallocarray(void *ptr, size_t onmemb, size_t nmemb, size_t size)
{
	void *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, size);
	ако (new_ptr == NULL)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	врати new_ptr;
}

char *
xstrdup(const char *str)
{
	size_t len;
	char *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	врати memcpy(cp, str, len);
}

цео
xvasprintf(char **ret, const char *fmt, va_list ap)
{
	цео i;

	i = vasprintf(ret, fmt, ap);
	ако (i < 0 || *ret == NULL)
		fatal("xvasprintf: could not allocate memory");
	врати i;
}

цео
xasprintf(char **ret, const char *fmt, ...)
{
	va_list ap;
	цео i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	врати i;
}
