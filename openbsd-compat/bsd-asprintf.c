/*
 * Copyright (c) 2004 Darren Tucker.
 *
 * Based originally on asprintf.c from OpenBSD:
 * Copyright (c) 1997 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#अन्तर्भाव "includes.h"

/*
 * Don't let systems with broken printf(3) avoid our replacements
 * via asprintf(3)/vasprintf(3) calling libc internally.
 */
#जइ defined(BROKEN_SNPRINTF)
# undef HAVE_VASPRINTF
# undef HAVE_ASPRINTF
#endif

#ifndef HAVE_VASPRINTF

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>

#define INIT_SZ	128

पूर्णाङ्क
vasprintf(वर्ण **str, ध्रुव वर्ण *fmt, va_list ap)
{
	पूर्णाङ्क ret = -1;
	va_list ap2;
	वर्ण *string, *newstr;
	size_t len;

	VA_COPY(ap2, ap);
	जइ ((string = malloc(INIT_SZ)) == रिक्त)
		गच्छ fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	जइ (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} अण्णहा जइ (ret == INT_MAX || ret < 0) { /* Bad length */
		मुक्त(string);
		गच्छ fail;
	} अण्णहा {	/* bigger than initial, realloc allowing for nul */
		len = (size_t)ret + 1;
		जइ ((newstr = realloc(string, len)) == रिक्त) {
			मुक्त(string);
			गच्छ fail;
		} अण्णहा {
			va_end(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			जइ (ret >= 0 && (size_t)ret < len) {
				*str = newstr;
			} अण्णहा { /* failed with realloc'ed string, give up */
				मुक्त(newstr);
				गच्छ fail;
			}
		}
	}
	va_end(ap2);
	प्रत्यागम (ret);

fail:
	*str = रिक्त;
	errno = ENOMEM;
	va_end(ap2);
	प्रत्यागम (-1);
}
#endif

#ifndef HAVE_ASPRINTF
पूर्णाङ्क asprintf(वर्ण **str, ध्रुव वर्ण *fmt, ...)
{
	va_list ap;
	पूर्णाङ्क ret;

	*str = रिक्त;
	va_start(ap, fmt);
	ret = vasprintf(str, fmt, ap);
	va_end(ap);

	प्रत्यागम ret;
}
#endif
