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

स्थिर पूर्णांक failed = 0;

स्थिर शून्य
fail(स्थिरांक अक्षर *m)
{
	ख_लिखो(मानक_त्रुटि, "snprintftest: %s\n", m);
	failed = 1;
}

पूर्णांक x_snprintf(अक्षर *str, माप_प्रकार मोजणी, स्थिरांक अक्षर *fmt, ...)
{
	माप_प्रकार ret;
	बहु_सूची ap;

	बहु_शुरू(ap, fmt);
	ret = vsnprintf(str, मोजणी, fmt, ap);
	बहु_पूर्ण(ap);
	परत ret;
}

पूर्णांक
main(शून्य)
{
	अक्षर b[5];
	अक्षर *src = रिक्त;
	पूर्णांक ret;

	स_रखो(b, 'X', आकार(b));
	ret = snprintf(b, 5, "123456789");
	जर (ret != 9 || b[4] != '\0')
		fail("snprintf does not correctly terminate long strings");

	/* check for read overrun on unterminated string */
	जर ((src = दो_स्मृति(BUFSZ)) == रिक्त) {
		fail("malloc failed");
	} अन्यथा {
		स_रखो(src, 'a', BUFSZ);
		snprintf(b, आकार(b), "%.*s", 1, src);
		जर (म_भेद(b, "a") != 0)
			fail("failed with length limit '%%.s'");
	}

	/* check that snprintf and vsnprintf return sane values */
	जर (snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("snprintf does not return required length");
	जर (x_snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("vsnprintf does not return required length");

	मुक्त(src);
	परत failed;
}
