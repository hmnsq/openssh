/*
 * Copyright (c) 2005 Darren Tucker
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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

स्थिर पूर्णाङ्क fail = 0;

शून्य
test(ध्रुव वर्ण *a)
{
	वर्ण *b;

	b = strdup(a);
	यदि (b == 0) {
		fail = 1;
		प्रत्यागम;
	}
	यदि (strcmp(a, b) != 0)
		fail = 1;
	मुक्त(b);
}

पूर्णाङ्क
main(शून्य)
{
	test("");
	test("a");
	test("\0");
	test("abcdefghijklmnopqrstuvwxyz");
	प्रत्यागम fail;
}
