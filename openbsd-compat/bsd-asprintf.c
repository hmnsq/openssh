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

#include "includes.h"

/*
 * Don't let systems with broken printf(3) avoid our replacements
 * via asprintf(3)/vasprintf(3) calling libc internally.
 */
#만약 defined(BROKEN_SNPRINTF)
# undef HAVE_VASPRINTF
# undef HAVE_ASPRINTF
#endif

#ifndef HAVE_VASPRINTF

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define INIT_SZ	128

정수
vasprintf(char **str, const char *fmt, va_list ap)
{
	정수 ret = -1;
	va_list ap2;
	char *string, *newstr;
	size_t len;

	VA_COPY(ap2, ap);
	만약 ((string = malloc(INIT_SZ)) == NULL)
		goto fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	만약 (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} 아니면 만약 (ret == INT_MAX || ret < 0) { /* Bad length */
		free(string);
		goto fail;
	} 아니면 {	/* bigger than initial, realloc allowing for nul */
		len = (size_t)ret + 1;
		만약 ((newstr = realloc(string, len)) == NULL) {
			free(string);
			goto fail;
		} 아니면 {
			va_end(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			만약 (ret >= 0 && (size_t)ret < len) {
				*str = newstr;
			} 아니면 { /* failed with realloc'ed string, give up */
				free(newstr);
				goto fail;
			}
		}
	}
	va_end(ap2);
	반환 (ret);

fail:
	*str = NULL;
	errno = ENOMEM;
	va_end(ap2);
	반환 (-1);
}
#endif

#ifndef HAVE_ASPRINTF
정수 asprintf(char **str, const char *fmt, ...)
{
	va_list ap;
	정수 ret;

	*str = NULL;
	va_start(ap, fmt);
	ret = vasprintf(str, fmt, ap);
	va_end(ap);

	반환 ret;
}
#endif
