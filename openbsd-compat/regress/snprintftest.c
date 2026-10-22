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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <string.h>

স্থির পূর্ণসংখ্যা failed = 0;

স্থির শূন্য
fail(ধ্রুবক অক্ষর *m)
{
	fprintf(stderr, "snprintftest: %s\n", m);
	failed = 1;
}

পূর্ণসংখ্যা x_snprintf(অক্ষর *str, আকার_t গুনতি, ধ্রুবক অক্ষর *fmt, ...)
{
	আকার_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, গুনতি, fmt, ap);
	va_end(ap);
	ফেরত ret;
}

পূর্ণসংখ্যা
প্রধান(শূন্য)
{
	অক্ষর b[5];
	অক্ষর *src = ফাঁকা;
	পূর্ণসংখ্যা ret;

	memset(b, 'X', আকার(b));
	ret = snprintf(b, 5, "123456789");
	যদি (ret != 9 || b[4] != '\0')
		fail("snprintf does not correctly terminate long strings");

	/* check for read overrun on unterminated string */
	যদি ((src = malloc(BUFSZ)) == ফাঁকা) {
		fail("malloc failed");
	} অন্যথা {
		memset(src, 'a', BUFSZ);
		snprintf(b, আকার(b), "%.*s", 1, src);
		যদি (strcmp(b, "a") != 0)
			fail("failed with length limit '%%.s'");
	}

	/* check that snprintf and vsnprintf return sane values */
	যদি (snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("snprintf does not return required length");
	যদি (x_snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("vsnprintf does not return required length");

	মুক্ত(src);
	ফেরত failed;
}
