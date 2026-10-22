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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "log.h"

#എങ്കിൽ defined(__OpenBSD__)
സ്ഥിരം അക്ഷരം * സ്ഥിരം malloc_options = "S";
#endif /* __OpenBSD__ */

ശൂന്യം *
xmalloc(size_t size)
{
	ശൂന്യം *ptr;

	എങ്കിൽ (size == 0)
		fatal("xmalloc: zero size");
	ptr = malloc(size);
	എങ്കിൽ (ptr == ശൂന്യ)
		fatal("xmalloc: out of memory (allocating %zu bytes)", size);
	തിരികെ ptr;
}

ശൂന്യം *
xcalloc(size_t nmemb, size_t size)
{
	ശൂന്യം *ptr;

	എങ്കിൽ (size == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	എങ്കിൽ (SIZE_MAX / nmemb < size)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = calloc(nmemb, size);
	എങ്കിൽ (ptr == ശൂന്യ)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    size * nmemb);
	തിരികെ ptr;
}

ശൂന്യം *
xreallocarray(ശൂന്യം *ptr, size_t nmemb, size_t size)
{
	ശൂന്യം *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, size);
	എങ്കിൽ (new_ptr == ശൂന്യ)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	തിരികെ new_ptr;
}

ശൂന്യം *
xrecallocarray(ശൂന്യം *ptr, size_t onmemb, size_t nmemb, size_t size)
{
	ശൂന്യം *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, size);
	എങ്കിൽ (new_ptr == ശൂന്യ)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	തിരികെ new_ptr;
}

അക്ഷരം *
xstrdup(സ്ഥിരം അക്ഷരം *str)
{
	size_t len;
	അക്ഷരം *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	തിരികെ memcpy(cp, str, len);
}

പൂർണ്ണസംഖ്യ
xvasprintf(അക്ഷരം **ret, സ്ഥിരം അക്ഷരം *fmt, va_list ap)
{
	പൂർണ്ണസംഖ്യ i;

	i = vasprintf(ret, fmt, ap);
	എങ്കിൽ (i < 0 || *ret == ശൂന്യ)
		fatal("xvasprintf: could not allocate memory");
	തിരികെ i;
}

പൂർണ്ണസംഖ്യ
xasprintf(അക്ഷരം **ret, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list ap;
	പൂർണ്ണസംഖ്യ i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	തിരികെ i;
}
