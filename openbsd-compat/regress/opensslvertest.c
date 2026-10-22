/*
 * Copyright (c) 2014 Darren Tucker
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

#समावेश "includes.h"

#समावेश <stdio.h>
#समावेश <stdlib.h>

पूर्णांक ssh_compatible_openssl(दीर्घ, दीर्घ);

काष्ठा version_test {
	दीर्घ headerver;
	दीर्घ libver;
	पूर्णांक परिणाम;
} version_tests[] = {
	/* built with 1.0.1b release headers */
	{ 0x1000101fL, 0x1000101fL, 1},/* exact match */
	{ 0x1000101fL, 0x1000102fL, 1},	/* newer library patch version: ok */
	{ 0x1000101fL, 0x1000100fL, 1},	/* older library patch version: ok */
	{ 0x1000101fL, 0x1000201fL, 1},	/* newer library fix version: ok */
	{ 0x1000101fL, 0x1000001fL, 0},	/* older library fix version: NO */
	{ 0x1000101fL, 0x1010101fL, 0},	/* newer library minor version: NO */
	{ 0x1000101fL, 0x0000101fL, 0},	/* older library major version: NO */
	{ 0x1000101fL, 0x2000101fL, 0},	/* newer library major version: NO */

	/* built with 1.1.1b release headers */
	{ 0x1010101fL, 0x1010101fL, 1},/* exact match */
	{ 0x1010101fL, 0x1010102fL, 1},	/* newer library patch version: ok */
	{ 0x1010101fL, 0x1010100fL, 1},	/* older library patch version: ok */
	{ 0x1010101fL, 0x1010201fL, 1},	/* newer library fix version: ok */
	{ 0x1010101fL, 0x1010001fL, 0},	/* older library fix version: NO */
	{ 0x1010101fL, 0x1020001fL, 0},	/* newer library minor version: NO */
	{ 0x1010101fL, 0x0010101fL, 0},	/* older library major version: NO */
	{ 0x1010101fL, 0x2010101fL, 0},	/* newer library major version: NO */

	/* built with 3.0.1 release headers */
	{ 0x3010101fL, 0x3010101fL, 1},/* exact match */
	{ 0x3010101fL, 0x3010102fL, 1},	/* newer library patch version: ok */
	{ 0x3010101fL, 0x3010100fL, 1},	/* older library patch version: ok */
	{ 0x3010101fL, 0x3010201fL, 1},	/* newer library fix version: ok */
	{ 0x3010101fL, 0x3010001fL, 1},	/* older library fix version: ok */
	{ 0x3010101fL, 0x3020001fL, 1},	/* newer library minor version: ok */
	{ 0x3010101fL, 0x1010101fL, 0},	/* older library major version: NO */
	{ 0x3010101fL, 0x4010101fL, 0},	/* newer library major version: NO */
};

व्योम
fail(दीर्घ hver, दीर्घ lver, पूर्णांक परिणाम)
{
	ख_लिखो(मानक_त्रुटि, "opensslver: header %lx library %lx != %d \n", hver, lver, परिणाम);
	निकास(1);
}

पूर्णांक
मुख्य(व्योम)
{
#अगर_घोषित WITH_OPENSSL
	अचिन्हित पूर्णांक i;
	पूर्णांक res;
	दीर्घ hver, lver;

	क्रम (i = 0; i < माप(version_tests) / माप(version_tests[0]); i++) {
		hver = version_tests[i].headerver;
		lver = version_tests[i].libver;
		res = version_tests[i].परिणाम;
		अगर (ssh_compatible_openssl(hver, lver) != res)
			fail(hver, lver, res);
	}
#पूर्ण_अगर
	निकास(0);
}
