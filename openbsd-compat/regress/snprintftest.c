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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>

સ્થિર પૂર્ણાંક failed = 0;

સ્થિર શૂન્ય
fail(અચલ અક્ષર *m)
{
	fprintf(stderr, "snprintftest: %s\n", m);
	failed = 1;
}

પૂર્ણાંક x_snprintf(અક્ષર *str, size_t ગણતરી, અચલ અક્ષર *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, ગણતરી, fmt, ap);
	va_end(ap);
	પાછા ret;
}

પૂર્ણાંક
મુખ્ય(શૂન્ય)
{
	અક્ષર b[5];
	અક્ષર *src = ખાલી;
	પૂર્ણાંક ret;

	memset(b, 'X', કદ(b));
	ret = snprintf(b, 5, "123456789");
	જો (ret != 9 || b[4] != '\0')
		fail("snprintf does not correctly terminate long strings");

	/* check for read overrun on unterminated string */
	જો ((src = malloc(BUFSZ)) == ખાલી) {
		fail("malloc failed");
	} નહીંતર {
		memset(src, 'a', BUFSZ);
		snprintf(b, કદ(b), "%.*s", 1, src);
		જો (strcmp(b, "a") != 0)
			fail("failed with length limit '%%.s'");
	}

	/* check that snprintf and vsnprintf return sane values */
	જો (snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("snprintf does not return required length");
	જો (x_snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("vsnprintf does not return required length");

	મુક્ત(src);
	પાછા failed;
}
