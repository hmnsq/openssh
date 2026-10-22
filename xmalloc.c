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

#यदि defined(__OpenBSD__)
ध्रुव वर्ण * ध्रुव malloc_options = "S";
#यदि_अन्तः /* __OpenBSD__ */

शून्य *
xmalloc(आकार_t आकार)
{
	शून्य *ptr;

	यदि (आकार == 0)
		fatal("xmalloc: zero size");
	ptr = स्मृतिं_देहि(आकार);
	यदि (ptr == रिक्त)
		fatal("xmalloc: out of memory (allocating %zu bytes)", आकार);
	प्रत्यागम ptr;
}

शून्य *
xcalloc(आकार_t nmemb, आकार_t आकार)
{
	शून्य *ptr;

	यदि (आकार == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	यदि (SIZE_MAX / nmemb < आकार)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = शून्यस्मृतिं_देहि(nmemb, आकार);
	यदि (ptr == रिक्त)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    आकार * nmemb);
	प्रत्यागम ptr;
}

शून्य *
xreallocarray(शून्य *ptr, आकार_t nmemb, आकार_t आकार)
{
	शून्य *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, आकार);
	यदि (new_ptr == रिक्त)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, आकार);
	प्रत्यागम new_ptr;
}

शून्य *
xrecallocarray(शून्य *ptr, आकार_t onmemb, आकार_t nmemb, आकार_t आकार)
{
	शून्य *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, आकार);
	यदि (new_ptr == रिक्त)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, आकार);
	प्रत्यागम new_ptr;
}

वर्ण *
xstrdup(ध्रुव वर्ण *str)
{
	आकार_t len;
	वर्ण *cp;

	len = वाक्यदैर्घ्यम्(str) + 1;
	cp = xmalloc(len);
	प्रत्यागम स्मृतिं_प्रतिलिख(cp, str, len);
}

पूर्णाङ्क
xvasprintf(वर्ण **ret, ध्रुव वर्ण *fmt, va_list ap)
{
	पूर्णाङ्क i;

	i = vasprintf(ret, fmt, ap);
	यदि (i < 0 || *ret == रिक्त)
		fatal("xvasprintf: could not allocate memory");
	प्रत्यागम i;
}

पूर्णाङ्क
xasprintf(वर्ण **ret, ध्रुव वर्ण *fmt, ...)
{
	va_list ap;
	पूर्णाङ्क i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	प्रत्यागम i;
}
