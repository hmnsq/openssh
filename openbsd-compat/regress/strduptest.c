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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

நிலையான முழு fail = 0;

வெறுமை
test(மாறிலி எழுத்து *a)
{
	எழுத்து *b;

	b = strdup(a);
	எனில் (b == 0) {
		fail = 1;
		திரும்பு;
	}
	எனில் (strcmp(a, b) != 0)
		fail = 1;
	விடுவி(b);
}

முழு
முதன்மை(வெறுமை)
{
	test("");
	test("a");
	test("\0");
	test("abcdefghijklmnopqrstuvwxyz");
	திரும்பு fail;
}
