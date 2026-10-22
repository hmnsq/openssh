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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

/*
 * Don't let systems with broken printf(3) avoid our replacements
 * via asprintf(3)/vasprintf(3) calling libc internally.
 */
#ਜੇ defined(BROKEN_SNPRINTF)
# undef HAVE_VASPRINTF
# undef HAVE_ASPRINTF
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_VASPRINTF

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ INIT_SZ	128

ਪੂਰਨ
vasprintf(ਅੱਖਰ **str, ਅਚਲ ਅੱਖਰ *fmt, va_list ap)
{
	ਪੂਰਨ ret = -1;
	va_list ap2;
	ਅੱਖਰ *string, *newstr;
	ਮਾਪ_t len;

	VA_COPY(ap2, ap);
	ਜੇ ((string = ਸਮ੍ਰਿਤੀ_ਦਿਓ(INIT_SZ)) == ਨਿਰਾ)
		ਜਾਓ fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	ਜੇ (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} ਨਹੀਂਤਾਂ ਜੇ (ret == ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ || ret < 0) { /* Bad length */
		ਮੁਕਤ(string);
		ਜਾਓ fail;
	} ਨਹੀਂਤਾਂ {	/* bigger than initial, realloc allowing for nul */
		len = (ਮਾਪ_t)ret + 1;
		ਜੇ ((newstr = realloc(string, len)) == ਨਿਰਾ) {
			ਮੁਕਤ(string);
			ਜਾਓ fail;
		} ਨਹੀਂਤਾਂ {
			va_end(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			ਜੇ (ret >= 0 && (ਮਾਪ_t)ret < len) {
				*str = newstr;
			} ਨਹੀਂਤਾਂ { /* failed with realloc'ed string, give up */
				ਮੁਕਤ(newstr);
				ਜਾਓ fail;
			}
		}
	}
	va_end(ap2);
	ਵਾਪਸ (ret);

fail:
	*str = ਨਿਰਾ;
	errno = ENOMEM;
	va_end(ap2);
	ਵਾਪਸ (-1);
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ASPRINTF
ਪੂਰਨ asprintf(ਅੱਖਰ **str, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ap;
	ਪੂਰਨ ret;

	*str = ਨਿਰਾ;
	va_start(ap, fmt);
	ret = vasprintf(str, fmt, ap);
	va_end(ap);

	ਵਾਪਸ ret;
}
#ਜੇ_ਅੰਤ
