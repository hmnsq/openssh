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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਜੇ defined(__OpenBSD__)
ਅਚਲ ਅੱਖਰ * ਅਚਲ malloc_options = "S";
#ਜੇ_ਅੰਤ /* __OpenBSD__ */

ਖਾਲੀ *
xmalloc(ਮਾਪ_t ਮਾਪ)
{
	ਖਾਲੀ *ptr;

	ਜੇ (ਮਾਪ == 0)
		fatal("xmalloc: zero size");
	ptr = ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਮਾਪ);
	ਜੇ (ptr == ਨਿਰਾ)
		fatal("xmalloc: out of memory (allocating %zu bytes)", ਮਾਪ);
	ਵਾਪਸ ptr;
}

ਖਾਲੀ *
xcalloc(ਮਾਪ_t nmemb, ਮਾਪ_t ਮਾਪ)
{
	ਖਾਲੀ *ptr;

	ਜੇ (ਮਾਪ == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	ਜੇ (SIZE_MAX / nmemb < ਮਾਪ)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(nmemb, ਮਾਪ);
	ਜੇ (ptr == ਨਿਰਾ)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    ਮਾਪ * nmemb);
	ਵਾਪਸ ptr;
}

ਖਾਲੀ *
xreallocarray(ਖਾਲੀ *ptr, ਮਾਪ_t nmemb, ਮਾਪ_t ਮਾਪ)
{
	ਖਾਲੀ *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, ਮਾਪ);
	ਜੇ (new_ptr == ਨਿਰਾ)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, ਮਾਪ);
	ਵਾਪਸ new_ptr;
}

ਖਾਲੀ *
xrecallocarray(ਖਾਲੀ *ptr, ਮਾਪ_t onmemb, ਮਾਪ_t nmemb, ਮਾਪ_t ਮਾਪ)
{
	ਖਾਲੀ *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, ਮਾਪ);
	ਜੇ (new_ptr == ਨਿਰਾ)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, ਮਾਪ);
	ਵਾਪਸ new_ptr;
}

ਅੱਖਰ *
xstrdup(ਅਚਲ ਅੱਖਰ *str)
{
	ਮਾਪ_t len;
	ਅੱਖਰ *cp;

	len = ਲੜੀ_ਲੰਬਾਈ(str) + 1;
	cp = xmalloc(len);
	ਵਾਪਸ ਸਮ੍ਰਿਤੀ_ਨਕਲ(cp, str, len);
}

ਪੂਰਨ
xvasprintf(ਅੱਖਰ **ret, ਅਚਲ ਅੱਖਰ *fmt, va_list ap)
{
	ਪੂਰਨ i;

	i = vasprintf(ret, fmt, ap);
	ਜੇ (i < 0 || *ret == ਨਿਰਾ)
		fatal("xvasprintf: could not allocate memory");
	ਵਾਪਸ i;
}

ਪੂਰਨ
xasprintf(ਅੱਖਰ **ret, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ap;
	ਪੂਰਨ i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	ਵਾਪਸ i;
}
