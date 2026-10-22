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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <string.h>

স্থির পূর্ণাঙ্ক failed = 0;

স্থির শূন্য
fail(ধ্রুৱ ৱর্ণ *m)
{
	fprintf(stderr, "snprintftest: %s\n", m);
	failed = 1;
}

পূর্ণাঙ্ক x_snprintf(ৱর্ণ *str, size_t গুনতি, ধ্রুৱ ৱর্ণ *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, গুনতি, fmt, ap);
	va_end(ap);
	ঘূৰাই ret;
}

পূর্ণাঙ্ক
main(শূন্য)
{
	ৱর্ণ b[5];
	ৱর্ণ *src = রিক্ত;
	পূর্ণাঙ্ক ret;

	memset(b, 'X', পরিমাণ(b));
	ret = snprintf(b, 5, "123456789");
	যদি (ret != 9 || b[4] != '\0')
		fail("snprintf does not correctly terminate long strings");

	/* check for read overrun on unterminated string */
	যদি ((src = malloc(BUFSZ)) == রিক্ত) {
		fail("malloc failed");
	} অন্যথা {
		memset(src, 'a', BUFSZ);
		snprintf(b, পরিমাণ(b), "%.*s", 1, src);
		যদি (strcmp(b, "a") != 0)
			fail("failed with length limit '%%.s'");
	}

	/* check that snprintf and vsnprintf return sane values */
	যদি (snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("snprintf does not return required length");
	যদি (x_snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("vsnprintf does not return required length");

	মুক্ত(src);
	ঘূৰাই failed;
}
