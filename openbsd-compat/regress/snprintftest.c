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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <string.h>

நிலையான முழு failed = 0;

நிலையான வெறுமை
fail(மாறிலி எழுத்து *m)
{
	fprintf(stderr, "snprintftest: %s\n", m);
	failed = 1;
}

முழு x_snprintf(எழுத்து *str, size_t மொத்தம், மாறிலி எழுத்து *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, மொத்தம், fmt, ap);
	va_end(ap);
	திரும்பு ret;
}

முழு
முதன்மை(வெறுமை)
{
	எழுத்து b[5];
	எழுத்து *src = வெற்று;
	முழு ret;

	memset(b, 'X', அளவு(b));
	ret = snprintf(b, 5, "123456789");
	எனில் (ret != 9 || b[4] != '\0')
		fail("snprintf does not correctly terminate long strings");

	/* check for read overrun on unterminated string */
	எனில் ((src = malloc(BUFSZ)) == வெற்று) {
		fail("malloc failed");
	} இல்லையெனில் {
		memset(src, 'a', BUFSZ);
		snprintf(b, அளவு(b), "%.*s", 1, src);
		எனில் (strcmp(b, "a") != 0)
			fail("failed with length limit '%%.s'");
	}

	/* check that snprintf and vsnprintf return sane values */
	எனில் (snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("snprintf does not return required length");
	எனில் (x_snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("vsnprintf does not return required length");

	விடுவி(src);
	திரும்பு failed;
}
