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

#ضمن "includes.h"

/*
 * Don't let systems with broken printf(3) avoid our replacements
 * via asprintf(3)/vasprintf(3) calling libc internally.
 */
#إذا defined(BROKEN_SNPRINTF)
# undef HAVE_VASPRINTF
# undef HAVE_ASPRINTF
#endif

#ifndef HAVE_VASPRINTF

#ضمن <errno.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>

#define INIT_SZ	128

صحيح
vasprintf(حرف **str, ثابت حرف *fmt, va_list ap)
{
	صحيح ret = -1;
	va_list ap2;
	حرف *string, *newstr;
	size_t len;

	VA_COPY(ap2, ap);
	إذا ((string = malloc(INIT_SZ)) == عدم)
		اذهب fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	إذا (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} وإلا إذا (ret == INT_MAX || ret < 0) { /* Bad length */
		حرر(string);
		اذهب fail;
	} وإلا {	/* bigger than initial, realloc allowing for nul */
		len = (size_t)ret + 1;
		إذا ((newstr = realloc(string, len)) == عدم) {
			حرر(string);
			اذهب fail;
		} وإلا {
			va_end(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			إذا (ret >= 0 && (size_t)ret < len) {
				*str = newstr;
			} وإلا { /* failed with realloc'ed string, give up */
				حرر(newstr);
				اذهب fail;
			}
		}
	}
	va_end(ap2);
	أرجع (ret);

fail:
	*str = عدم;
	errno = ENOMEM;
	va_end(ap2);
	أرجع (-1);
}
#endif

#ifndef HAVE_ASPRINTF
صحيح asprintf(حرف **str, ثابت حرف *fmt, ...)
{
	va_list ap;
	صحيح ret;

	*str = عدم;
	va_start(ap, fmt);
	ret = vasprintf(str, fmt, ap);
	va_end(ap);

	أرجع ret;
}
#endif
