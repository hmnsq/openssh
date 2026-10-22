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

#నిర్వచించు BUFSZ 2048

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>

స్థిర పూర్ణాంకం failed = 0;

స్థిర శూన్య
fail(స్థిరరాశి అక్షరం *m)
{
	fprintf(stderr, "snprintftest: %s\n", m);
	failed = 1;
}

పూర్ణాంకం x_snprintf(అక్షరం *str, కొలత_t లెక్క, స్థిరరాశి అక్షరం *fmt, ...)
{
	కొలత_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, లెక్క, fmt, ap);
	va_end(ap);
	తిరిగి ret;
}

పూర్ణాంకం
ప్రధాన(శూన్య)
{
	అక్షరం b[5];
	అక్షరం *src = ఖాళీ;
	పూర్ణాంకం ret;

	memset(b, 'X', పరిమాణం(b));
	ret = snprintf(b, 5, "123456789");
	ఒకవేళ (ret != 9 || b[4] != '\0')
		fail("snprintf does not correctly terminate long strings");

	/* check for read overrun on unterminated string */
	ఒకవేళ ((src = జ్ఞాపకం_ఇవ్వు(BUFSZ)) == ఖాళీ) {
		fail("malloc failed");
	} లేకపోతే {
		memset(src, 'a', BUFSZ);
		snprintf(b, పరిమాణం(b), "%.*s", 1, src);
		ఒకవేళ (strcmp(b, "a") != 0)
			fail("failed with length limit '%%.s'");
	}

	/* check that snprintf and vsnprintf return sane values */
	ఒకవేళ (snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("snprintf does not return required length");
	ఒకవేళ (x_snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("vsnprintf does not return required length");

	విడుదల(src);
	తిరిగి failed;
}
