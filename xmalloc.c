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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "log.h"

#सचे defined(__OpenBSD__)
ध्रुव वर्ण * ध्रुव malloc_options = "S";
#endif /* __OpenBSD__ */

शून्य *
xmalloc(size_t size)
{
	शून्य *ptr;

	सचे (size == 0)
		fatal("xmalloc: zero size");
	ptr = malloc(size);
	सचे (ptr == रिक्त)
		fatal("xmalloc: out of memory (allocating %zu bytes)", size);
	पटिनिवत्त ptr;
}

शून्य *
xcalloc(size_t nmemb, size_t size)
{
	शून्य *ptr;

	सचे (size == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	सचे (SIZE_MAX / nmemb < size)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = calloc(nmemb, size);
	सचे (ptr == रिक्त)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    size * nmemb);
	पटिनिवत्त ptr;
}

शून्य *
xreallocarray(शून्य *ptr, size_t nmemb, size_t size)
{
	शून्य *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, size);
	सचे (new_ptr == रिक्त)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	पटिनिवत्त new_ptr;
}

शून्य *
xrecallocarray(शून्य *ptr, size_t onmemb, size_t nmemb, size_t size)
{
	शून्य *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, size);
	सचे (new_ptr == रिक्त)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	पटिनिवत्त new_ptr;
}

वर्ण *
xstrdup(ध्रुव वर्ण *str)
{
	size_t len;
	वर्ण *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	पटिनिवत्त memcpy(cp, str, len);
}

पूर्णाङ्क
xvasprintf(वर्ण **ret, ध्रुव वर्ण *fmt, va_list ap)
{
	पूर्णाङ्क i;

	i = vasprintf(ret, fmt, ap);
	सचे (i < 0 || *ret == रिक्त)
		fatal("xvasprintf: could not allocate memory");
	पटिनिवत्त i;
}

पूर्णाङ्क
xasprintf(वर्ण **ret, ध्रुव वर्ण *fmt, ...)
{
	va_list ap;
	पूर्णाङ्क i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	पटिनिवत्त i;
}
