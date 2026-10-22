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

#அந்தர்பாவ "includes.h"

/*
 * Don't let systems with broken printf(3) avoid our replacements
 * via asprintf(3)/vasprintf(3) calling libc internally.
 */
#எனில் defined(BROKEN_SNPRINTF)
# undef HAVE_VASPRINTF
# undef HAVE_ASPRINTF
#endif

#ifndef HAVE_VASPRINTF

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>

#define INIT_SZ	128

முழு
vasprintf(எழுத்து **str, மாறிலி எழுத்து *fmt, va_list ap)
{
	முழு ret = -1;
	va_list ap2;
	எழுத்து *string, *newstr;
	size_t len;

	VA_COPY(ap2, ap);
	எனில் ((string = malloc(INIT_SZ)) == வெற்று)
		செல் fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	எனில் (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} இல்லையெனில் எனில் (ret == INT_MAX || ret < 0) { /* Bad length */
		விடுவி(string);
		செல் fail;
	} இல்லையெனில் {	/* bigger than initial, realloc allowing for nul */
		len = (size_t)ret + 1;
		எனில் ((newstr = realloc(string, len)) == வெற்று) {
			விடுவி(string);
			செல் fail;
		} இல்லையெனில் {
			va_end(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			எனில் (ret >= 0 && (size_t)ret < len) {
				*str = newstr;
			} இல்லையெனில் { /* failed with realloc'ed string, give up */
				விடுவி(newstr);
				செல் fail;
			}
		}
	}
	va_end(ap2);
	திரும்பு (ret);

fail:
	*str = வெற்று;
	errno = ENOMEM;
	va_end(ap2);
	திரும்பு (-1);
}
#endif

#ifndef HAVE_ASPRINTF
முழு asprintf(எழுத்து **str, மாறிலி எழுத்து *fmt, ...)
{
	va_list ap;
	முழு ret;

	*str = வெற்று;
	va_start(ap, fmt);
	ret = vasprintf(str, fmt, ap);
	va_end(ap);

	திரும்பு ret;
}
#endif
