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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <stdarg.h>
#شامل <string.h>

ایستا صحیح failed = 0;

ایستا تهی
fail(ثابت نویسه *m)
{
	fprintf(stderr, "snprintftest: %s\n", m);
	failed = 1;
}

صحیح x_snprintf(نویسه *str, size_t شمار, ثابت نویسه *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, شمار, fmt, ap);
	va_end(ap);
	بازگشت ret;
}

صحیح
اصلی(تهی)
{
	نویسه b[5];
	نویسه *src = پوچ;
	صحیح ret;

	memset(b, 'X', اندازه(b));
	ret = snprintf(b, 5, "123456789");
	اگر (ret != 9 || b[4] != '\0')
		fail("snprintf does not correctly terminate long strings");

	/* check for read overrun on unterminated string */
	اگر ((src = malloc(BUFSZ)) == پوچ) {
		fail("malloc failed");
	} وگرنه {
		memset(src, 'a', BUFSZ);
		snprintf(b, اندازه(b), "%.*s", 1, src);
		اگر (strcmp(b, "a") != 0)
			fail("failed with length limit '%%.s'");
	}

	/* check that snprintf and vsnprintf return sane values */
	اگر (snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("snprintf does not return required length");
	اگر (x_snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("vsnprintf does not return required length");

	آزاد(src);
	بازگشت failed;
}
