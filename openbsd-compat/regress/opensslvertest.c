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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>

पूर्णाङ्क ssh_compatible_openssl(long, long);

संरचना version_test {
	long headerver;
	long libver;
	पूर्णाङ्क result;
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

शून्य
fail(long hver, long lver, पूर्णाङ्क result)
{
	fprintf(stderr, "opensslver: header %lx library %lx != %d \n", hver, lver, result);
	exit(1);
}

पूर्णाङ्क
main(शून्य)
{
#ifdef WITH_OPENSSL
	unsigned पूर्णाङ्क i;
	पूर्णाङ्क res;
	long hver, lver;

	प्रति (i = 0; i < परिमाण(version_tests) / परिमाण(version_tests[0]); i++) {
		hver = version_tests[i].headerver;
		lver = version_tests[i].libver;
		res = version_tests[i].result;
		यदि (ssh_compatible_openssl(hver, lver) != res)
			fail(hver, lver, res);
	}
#endif
	exit(0);
}
