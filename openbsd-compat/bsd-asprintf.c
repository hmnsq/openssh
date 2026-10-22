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

#અન્તર્ભાવ "includes.h"

/*
 * Don't let systems with broken printf(3) avoid our replacements
 * via asprintf(3)/vasprintf(3) calling libc internally.
 */
#જો defined(BROKEN_SNPRINTF)
# undef HAVE_VASPRINTF
# undef HAVE_ASPRINTF
#endif

#ifndef HAVE_VASPRINTF

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>

#define INIT_SZ	128

પૂર્ણાંક
vasprintf(અક્ષર **str, અચલ અક્ષર *fmt, va_list ap)
{
	પૂર્ણાંક ret = -1;
	va_list ap2;
	અક્ષર *string, *newstr;
	size_t len;

	VA_COPY(ap2, ap);
	જો ((string = malloc(INIT_SZ)) == ખાલી)
		જાઓ fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	જો (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} નહીંતર જો (ret == INT_MAX || ret < 0) { /* Bad length */
		મુક્ત(string);
		જાઓ fail;
	} નહીંતર {	/* bigger than initial, realloc allowing for nul */
		len = (size_t)ret + 1;
		જો ((newstr = realloc(string, len)) == ખાલી) {
			મુક્ત(string);
			જાઓ fail;
		} નહીંતર {
			va_end(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			જો (ret >= 0 && (size_t)ret < len) {
				*str = newstr;
			} નહીંતર { /* failed with realloc'ed string, give up */
				મુક્ત(newstr);
				જાઓ fail;
			}
		}
	}
	va_end(ap2);
	પાછા (ret);

fail:
	*str = ખાલી;
	errno = ENOMEM;
	va_end(ap2);
	પાછા (-1);
}
#endif

#ifndef HAVE_ASPRINTF
પૂર્ણાંક asprintf(અક્ષર **str, અચલ અક્ષર *fmt, ...)
{
	va_list ap;
	પૂર્ણાંક ret;

	*str = ખાલી;
	va_start(ap, fmt);
	ret = vasprintf(str, fmt, ap);
	va_end(ap);

	પાછા ret;
}
#endif
