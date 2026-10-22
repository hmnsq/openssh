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

#ضمن "includes.h"

#ضمن <stdarg.h>
#ضمن <stdint.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "xmalloc.h"
#ضمن "log.h"

#𐤀𐤌 defined(__OpenBSD__)
ثابت حرف * ثابت malloc_options = "S";
#endif /* __OpenBSD__ */

فراغ *
xmalloc(size_t size)
{
	فراغ *ptr;

	𐤀𐤌 (size == 0)
		fatal("xmalloc: zero size");
	ptr = malloc(size);
	𐤀𐤌 (ptr == عدم)
		fatal("xmalloc: out of memory (allocating %zu bytes)", size);
	أرجع ptr;
}

فراغ *
xcalloc(size_t nmemb, size_t size)
{
	فراغ *ptr;

	𐤀𐤌 (size == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	𐤀𐤌 (SIZE_MAX / nmemb < size)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = calloc(nmemb, size);
	𐤀𐤌 (ptr == عدم)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    size * nmemb);
	أرجع ptr;
}

فراغ *
xreallocarray(فراغ *ptr, size_t nmemb, size_t size)
{
	فراغ *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, size);
	𐤀𐤌 (new_ptr == عدم)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	أرجع new_ptr;
}

فراغ *
xrecallocarray(فراغ *ptr, size_t onmemb, size_t nmemb, size_t size)
{
	فراغ *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, size);
	𐤀𐤌 (new_ptr == عدم)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	أرجع new_ptr;
}

حرف *
xstrdup(ثابت حرف *str)
{
	size_t len;
	حرف *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	أرجع memcpy(cp, str, len);
}

صحيح
xvasprintf(حرف **ret, ثابت حرف *fmt, va_list ap)
{
	صحيح i;

	i = vasprintf(ret, fmt, ap);
	𐤀𐤌 (i < 0 || *ret == عدم)
		fatal("xvasprintf: could not allocate memory");
	أرجع i;
}

صحيح
xasprintf(حرف **ret, ثابت حرف *fmt, ...)
{
	va_list ap;
	صحيح i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	أرجع i;
}
