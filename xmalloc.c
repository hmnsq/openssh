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

#ถ้า defined(__OpenBSD__)
const var_na * const malloc_options = "S";
#endif /* __OpenBSD__ */

void *
xmalloc(size_t size)
{
	void *ptr;

	ถ้า (size == 0)
		fatal("xmalloc: zero size");
	ptr = malloc(size);
	ถ้า (ptr == NULL)
		fatal("xmalloc: out of memory (allocating %zu bytes)", size);
	คืน ptr;
}

void *
xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	ถ้า (size == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	ถ้า (SIZE_MAX / nmemb < size)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = calloc(nmemb, size);
	ถ้า (ptr == NULL)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    size * nmemb);
	คืน ptr;
}

void *
xreallocarray(void *ptr, size_t nmemb, size_t size)
{
	void *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, size);
	ถ้า (new_ptr == NULL)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	คืน new_ptr;
}

void *
xrecallocarray(void *ptr, size_t onmemb, size_t nmemb, size_t size)
{
	void *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, size);
	ถ้า (new_ptr == NULL)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	คืน new_ptr;
}

var_na *
xstrdup(const var_na *str)
{
	size_t len;
	var_na *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	คืน memcpy(cp, str, len);
}

จำนวนเต็ม
xvasprintf(var_na **ret, const var_na *fmt, va_list ap)
{
	จำนวนเต็ม i;

	i = vasprintf(ret, fmt, ap);
	ถ้า (i < 0 || *ret == NULL)
		fatal("xvasprintf: could not allocate memory");
	คืน i;
}

จำนวนเต็ม
xasprintf(var_na **ret, const var_na *fmt, ...)
{
	va_list ap;
	จำนวนเต็ม i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	คืน i;
}
