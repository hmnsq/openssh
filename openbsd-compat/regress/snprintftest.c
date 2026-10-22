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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା failed = 0;

ସ୍ଥିର ଶୂନ୍ୟ
fail(ଅଚଳ ଅକ୍ଷର *m)
{
	fprintf(stderr, "snprintftest: %s\n", m);
	failed = 1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା x_snprintf(ଅକ୍ଷର *str, size_t ଗଣନା_2, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, ଗଣନା_2, fmt, ap);
	va_end(ap);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର b[5];
	ଅକ୍ଷର *src = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;

	memset(b, 'X', ଆକାର(b));
	ret = snprintf(b, 5, "123456789");
	ଯଦି (ret != 9 || b[4] != '\0')
		fail("snprintf does not correctly terminate long strings");

	/* check for read overrun on unterminated string */
	ଯଦି ((src = malloc(BUFSZ)) == ଖାଲି) {
		fail("malloc failed");
	} ଅନ୍ୟଥା {
		memset(src, 'a', BUFSZ);
		snprintf(b, ଆକାର(b), "%.*s", 1, src);
		ଯଦି (strcmp(b, "a") != 0)
			fail("failed with length limit '%%.s'");
	}

	/* check that snprintf and vsnprintf return sane values */
	ଯଦି (snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("snprintf does not return required length");
	ଯଦି (x_snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("vsnprintf does not return required length");

	ମୁକ୍ତ(src);
	ଫେରନ୍ତୁ failed;
}
