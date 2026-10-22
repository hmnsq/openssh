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

#ଅନ୍ତର୍ଭାଵ "includes.h"

/*
 * Don't let systems with broken printf(3) avoid our replacements
 * via asprintf(3)/vasprintf(3) calling libc internally.
 */
#ଯଦି defined(BROKEN_SNPRINTF)
# undef HAVE_VASPRINTF
# undef HAVE_ASPRINTF
#endif

#ifndef HAVE_VASPRINTF

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>

#define INIT_SZ	128

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
vasprintf(ଅକ୍ଷର **str, ଅଚଳ ଅକ୍ଷର *fmt, va_list ap)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;
	va_list ap2;
	ଅକ୍ଷର *string, *newstr;
	size_t len;

	VA_COPY(ap2, ap);
	ଯଦି ((string = malloc(INIT_SZ)) == ଖାଲି)
		ଯାଅ fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	ଯଦି (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} ଅନ୍ୟଥା ଯଦି (ret == INT_MAX || ret < 0) { /* Bad length */
		ମୁକ୍ତ(string);
		ଯାଅ fail;
	} ଅନ୍ୟଥା {	/* bigger than initial, realloc allowing for nul */
		len = (size_t)ret + 1;
		ଯଦି ((newstr = realloc(string, len)) == ଖାଲି) {
			ମୁକ୍ତ(string);
			ଯାଅ fail;
		} ଅନ୍ୟଥା {
			va_end(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			ଯଦି (ret >= 0 && (size_t)ret < len) {
				*str = newstr;
			} ଅନ୍ୟଥା { /* failed with realloc'ed string, give up */
				ମୁକ୍ତ(newstr);
				ଯାଅ fail;
			}
		}
	}
	va_end(ap2);
	ଫେରନ୍ତୁ (ret);

fail:
	*str = ଖାଲି;
	errno = ENOMEM;
	va_end(ap2);
	ଫେରନ୍ତୁ (-1);
}
#endif

#ifndef HAVE_ASPRINTF
ପୂର୍ଣ୍ଣସଂଖ୍ୟା asprintf(ଅକ୍ଷର **str, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list ap;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;

	*str = ଖାଲି;
	va_start(ap, fmt);
	ret = vasprintf(str, fmt, ap);
	va_end(ap);

	ଫେରନ୍ତୁ ret;
}
#endif
