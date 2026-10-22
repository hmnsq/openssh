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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>

स्थिर पूर्णाङ्क failed = 0;

स्थिर शून्य
fail(ध्रुव वर्ण *m)
{
	ख_लिखो(मानक_त्रुटि, "snprintftest: %s\n", m);
	failed = 1;
}

पूर्णाङ्क x_snprintf(वर्ण *str, माप_प्रकार गिनती, ध्रुव वर्ण *fmt, ...)
{
	माप_प्रकार ret;
	बहु_सूची ap;

	बहु_शुरू(ap, fmt);
	ret = vsnprintf(str, गिनती, fmt, ap);
	बहु_पूर्ण(ap);
	प्रत्यागम ret;
}

पूर्णाङ्क
main(शून्य)
{
	वर्ण b[5];
	वर्ण *src = रिक्त;
	पूर्णाङ्क ret;

	स_रखो(b, 'X', परिमाण(b));
	ret = snprintf(b, 5, "123456789");
	यदि (ret != 9 || b[4] != '\0')
		fail("snprintf does not correctly terminate long strings");

	/* check for read overrun on unterminated string */
	यदि ((src = दो_स्मृति(BUFSZ)) == रिक्त) {
		fail("malloc failed");
	} अन्यथा {
		स_रखो(src, 'a', BUFSZ);
		snprintf(b, परिमाण(b), "%.*s", 1, src);
		यदि (म_भेद(b, "a") != 0)
			fail("failed with length limit '%%.s'");
	}

	/* check that snprintf and vsnprintf return sane values */
	यदि (snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("snprintf does not return required length");
	यदि (x_snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("vsnprintf does not return required length");

	मुक्त(src);
	प्रत्यागम failed;
}
