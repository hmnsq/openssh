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

#অন্তর্ভাৱ "includes.h"

/*
 * Don't let systems with broken printf(3) avoid our replacements
 * via asprintf(3)/vasprintf(3) calling libc internally.
 */
#যদি defined(BROKEN_SNPRINTF)
# undef HAVE_VASPRINTF
# undef HAVE_ASPRINTF
#endif

#ifndef HAVE_VASPRINTF

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>

#define INIT_SZ	128

পূর্ণাঙ্ক
vasprintf(ৱর্ণ **str, ধ্রুৱ ৱর্ণ *fmt, va_list ap)
{
	পূর্ণাঙ্ক ret = -1;
	va_list ap2;
	ৱর্ণ *string, *newstr;
	size_t len;

	VA_COPY(ap2, ap);
	যদি ((string = malloc(INIT_SZ)) == রিক্ত)
		গচ্ছ fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	যদি (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} অন্যথা যদি (ret == INT_MAX || ret < 0) { /* Bad length */
		মুক্ত(string);
		গচ্ছ fail;
	} অন্যথা {	/* bigger than initial, realloc allowing for nul */
		len = (size_t)ret + 1;
		যদি ((newstr = realloc(string, len)) == রিক্ত) {
			মুক্ত(string);
			গচ্ছ fail;
		} অন্যথা {
			va_end(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			যদি (ret >= 0 && (size_t)ret < len) {
				*str = newstr;
			} অন্যথা { /* failed with realloc'ed string, give up */
				মুক্ত(newstr);
				গচ্ছ fail;
			}
		}
	}
	va_end(ap2);
	ঘূৰাই (ret);

fail:
	*str = রিক্ত;
	errno = ENOMEM;
	va_end(ap2);
	ঘূৰাই (-1);
}
#endif

#ifndef HAVE_ASPRINTF
পূর্ণাঙ্ক asprintf(ৱর্ণ **str, ধ্রুৱ ৱর্ণ *fmt, ...)
{
	va_list ap;
	পূর্ণাঙ্ক ret;

	*str = রিক্ত;
	va_start(ap, fmt);
	ret = vasprintf(str, fmt, ap);
	va_end(ap);

	ঘূৰাই ret;
}
#endif
