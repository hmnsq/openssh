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

#ಅನ್ತರ್ಭಾವ "includes.h"

/*
 * Don't let systems with broken printf(3) avoid our replacements
 * via asprintf(3)/vasprintf(3) calling libc internally.
 */
#ಯದಿ defined(BROKEN_SNPRINTF)
# undef HAVE_VASPRINTF
# undef HAVE_ASPRINTF
#endif

#ifndef HAVE_VASPRINTF

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

#define INIT_SZ	128

ಪೂರ್ಣಾಙ್ಕ
vasprintf(ವರ್ಣ **str, ಧ್ರುವ ವರ್ಣ *fmt, va_list ap)
{
	ಪೂರ್ಣಾಙ್ಕ ret = -1;
	va_list ap2;
	ವರ್ಣ *string, *newstr;
	size_t len;

	VA_COPY(ap2, ap);
	ಯದಿ ((string = malloc(INIT_SZ)) == ರಿಕ್ತ)
		ಗಚ್ಛ fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	ಯದಿ (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} ಅನ್ಯಥಾ ಯದಿ (ret == INT_MAX || ret < 0) { /* Bad length */
		ಮುಕ್ತ(string);
		ಗಚ್ಛ fail;
	} ಅನ್ಯಥಾ {	/* bigger than initial, realloc allowing for nul */
		len = (size_t)ret + 1;
		ಯದಿ ((newstr = realloc(string, len)) == ರಿಕ್ತ) {
			ಮುಕ್ತ(string);
			ಗಚ್ಛ fail;
		} ಅನ್ಯಥಾ {
			va_end(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			ಯದಿ (ret >= 0 && (size_t)ret < len) {
				*str = newstr;
			} ಅನ್ಯಥಾ { /* failed with realloc'ed string, give up */
				ಮುಕ್ತ(newstr);
				ಗಚ್ಛ fail;
			}
		}
	}
	va_end(ap2);
	ಪ್ರತ್ಯಾಗಮ (ret);

fail:
	*str = ರಿಕ್ತ;
	errno = ENOMEM;
	va_end(ap2);
	ಪ್ರತ್ಯಾಗಮ (-1);
}
#endif

#ifndef HAVE_ASPRINTF
ಪೂರ್ಣಾಙ್ಕ asprintf(ವರ್ಣ **str, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list ap;
	ಪೂರ್ಣಾಙ್ಕ ret;

	*str = ರಿಕ್ತ;
	va_start(ap, fmt);
	ret = vasprintf(str, fmt, ap);
	va_end(ap);

	ಪ್ರತ್ಯಾಗಮ ret;
}
#endif
