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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#ಯದಿ defined(__OpenBSD__)
ಧ್ರುವ ವರ್ಣ * ಧ್ರುವ malloc_options = "S";
#endif /* __OpenBSD__ */

ಶೂನ್ಯ *
xmalloc(size_t size)
{
	ಶೂನ್ಯ *ptr;

	ಯದಿ (size == 0)
		fatal("xmalloc: zero size");
	ptr = malloc(size);
	ಯದಿ (ptr == ರಿಕ್ತ)
		fatal("xmalloc: out of memory (allocating %zu bytes)", size);
	ಪ್ರತ್ಯಾಗಮ ptr;
}

ಶೂನ್ಯ *
xcalloc(size_t nmemb, size_t size)
{
	ಶೂನ್ಯ *ptr;

	ಯದಿ (size == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	ಯದಿ (SIZE_MAX / nmemb < size)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = calloc(nmemb, size);
	ಯದಿ (ptr == ರಿಕ್ತ)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    size * nmemb);
	ಪ್ರತ್ಯಾಗಮ ptr;
}

ಶೂನ್ಯ *
xreallocarray(ಶೂನ್ಯ *ptr, size_t nmemb, size_t size)
{
	ಶೂನ್ಯ *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, size);
	ಯದಿ (new_ptr == ರಿಕ್ತ)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	ಪ್ರತ್ಯಾಗಮ new_ptr;
}

ಶೂನ್ಯ *
xrecallocarray(ಶೂನ್ಯ *ptr, size_t onmemb, size_t nmemb, size_t size)
{
	ಶೂನ್ಯ *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, size);
	ಯದಿ (new_ptr == ರಿಕ್ತ)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	ಪ್ರತ್ಯಾಗಮ new_ptr;
}

ವರ್ಣ *
xstrdup(ಧ್ರುವ ವರ್ಣ *str)
{
	size_t len;
	ವರ್ಣ *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	ಪ್ರತ್ಯಾಗಮ memcpy(cp, str, len);
}

ಪೂರ್ಣಾಙ್ಕ
xvasprintf(ವರ್ಣ **ret, ಧ್ರುವ ವರ್ಣ *fmt, va_list ap)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	i = vasprintf(ret, fmt, ap);
	ಯದಿ (i < 0 || *ret == ರಿಕ್ತ)
		fatal("xvasprintf: could not allocate memory");
	ಪ್ರತ್ಯಾಗಮ i;
}

ಪೂರ್ಣಾಙ್ಕ
xasprintf(ವರ್ಣ **ret, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list ap;
	ಪೂರ್ಣಾಙ್ಕ i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	ಪ್ರತ್ಯಾಗಮ i;
}
