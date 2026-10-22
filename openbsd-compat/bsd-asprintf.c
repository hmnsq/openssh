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

#شامل "includes.h"

/*
 * Don't let systems with broken printf(3) avoid our replacements
 * via asprintf(3)/vasprintf(3) calling libc internally.
 */
#اگر defined(BROKEN_SNPRINTF)
# undef HAVE_VASPRINTF
# undef HAVE_ASPRINTF
#endif

#ifndef HAVE_VASPRINTF

#شامل <errno.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>

#define INIT_SZ	128

صحیح
vasprintf(نویسه **str, ثابت نویسه *fmt, va_list ap)
{
	صحیح ret = -1;
	va_list ap2;
	نویسه *string, *newstr;
	size_t len;

	VA_COPY(ap2, ap);
	اگر ((string = malloc(INIT_SZ)) == پوچ)
		برو fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	اگر (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} وگرنه اگر (ret == INT_MAX || ret < 0) { /* Bad length */
		آزاد(string);
		برو fail;
	} وگرنه {	/* bigger than initial, realloc allowing for nul */
		len = (size_t)ret + 1;
		اگر ((newstr = realloc(string, len)) == پوچ) {
			آزاد(string);
			برو fail;
		} وگرنه {
			va_end(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			اگر (ret >= 0 && (size_t)ret < len) {
				*str = newstr;
			} وگرنه { /* failed with realloc'ed string, give up */
				آزاد(newstr);
				برو fail;
			}
		}
	}
	va_end(ap2);
	بازگشت (ret);

fail:
	*str = پوچ;
	errno = ENOMEM;
	va_end(ap2);
	بازگشت (-1);
}
#endif

#ifndef HAVE_ASPRINTF
صحیح asprintf(نویسه **str, ثابت نویسه *fmt, ...)
{
	va_list ap;
	صحیح ret;

	*str = پوچ;
	va_start(ap, fmt);
	ret = vasprintf(str, fmt, ap);
	va_end(ap);

	بازگشت ret;
}
#endif
