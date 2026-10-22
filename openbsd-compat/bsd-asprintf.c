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

#അന്തര്ഭാവ "includes.h"

/*
 * Don't let systems with broken printf(3) avoid our replacements
 * via asprintf(3)/vasprintf(3) calling libc internally.
 */
#എങ്കിൽ defined(BROKEN_SNPRINTF)
# undef HAVE_VASPRINTF
# undef HAVE_ASPRINTF
#endif

#ifndef HAVE_VASPRINTF

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>

#define INIT_SZ	128

പൂർണ്ണസംഖ്യ
vasprintf(അക്ഷരം **str, സ്ഥിരം അക്ഷരം *fmt, va_list ap)
{
	പൂർണ്ണസംഖ്യ ret = -1;
	va_list ap2;
	അക്ഷരം *string, *newstr;
	size_t len;

	VA_COPY(ap2, ap);
	എങ്കിൽ ((string = malloc(INIT_SZ)) == ശൂന്യ)
		പോകുക fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	എങ്കിൽ (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} അല്ലെങ്കിൽ എങ്കിൽ (ret == INT_MAX || ret < 0) { /* Bad length */
		സ്വതന്ത്രം(string);
		പോകുക fail;
	} അല്ലെങ്കിൽ {	/* bigger than initial, realloc allowing for nul */
		len = (size_t)ret + 1;
		എങ്കിൽ ((newstr = realloc(string, len)) == ശൂന്യ) {
			സ്വതന്ത്രം(string);
			പോകുക fail;
		} അല്ലെങ്കിൽ {
			va_end(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			എങ്കിൽ (ret >= 0 && (size_t)ret < len) {
				*str = newstr;
			} അല്ലെങ്കിൽ { /* failed with realloc'ed string, give up */
				സ്വതന്ത്രം(newstr);
				പോകുക fail;
			}
		}
	}
	va_end(ap2);
	തിരികെ (ret);

fail:
	*str = ശൂന്യ;
	errno = ENOMEM;
	va_end(ap2);
	തിരികെ (-1);
}
#endif

#ifndef HAVE_ASPRINTF
പൂർണ്ണസംഖ്യ asprintf(അക്ഷരം **str, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list ap;
	പൂർണ്ണസംഖ്യ ret;

	*str = ശൂന്യ;
	va_start(ap, fmt);
	ret = vasprintf(str, fmt, ap);
	va_end(ap);

	തിരികെ ret;
}
#endif
