/*
 * Copyright (c) 2005 Darren Tucker
 * Copyright (c) 2005 Damien Miller
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

#define BUFSZ 2048

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <stdarg.h>
#ضمن <string.h>

ساكن صحيح failed = 0;

ساكن فراغ
fail(ثابت حرف *m)
{
	fprintf(stderr, "snprintftest: %s\n", m);
	failed = 1;
}

صحيح x_snprintf(حرف *str, size_t count, ثابت حرف *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, count, fmt, ap);
	va_end(ap);
	החזר ret;
}

صحيح
main(فراغ)
{
	حرف b[5];
	حرف *src = عدم;
	صحيح ret;

	memset(b, 'X', حجم(b));
	ret = snprintf(b, 5, "123456789");
	אם (ret != 9 || b[4] != '\0')
		fail("snprintf does not correctly terminate long strings");

	/* check for read overrun on unterminated string */
	אם ((src = malloc(BUFSZ)) == عدم) {
		fail("malloc failed");
	} אחרת {
		memset(src, 'a', BUFSZ);
		snprintf(b, حجم(b), "%.*s", 1, src);
		אם (strcmp(b, "a") != 0)
			fail("failed with length limit '%%.s'");
	}

	/* check that snprintf and vsnprintf return sane values */
	אם (snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("snprintf does not return required length");
	אם (x_snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("vsnprintf does not return required length");

	حرر(src);
	החזר failed;
}
