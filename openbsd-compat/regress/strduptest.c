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

#include "includes.h"

#include <stdlib.h>
#include <string.h>

static ຈຳນວນເຕັມ fail = 0;

void
test(const var_na *a)
{
	var_na *b;

	b = strdup(a);
	ຖ້າ (b == 0) {
		fail = 1;
		ສົ່ງຄືນ;
	}
	ຖ້າ (strcmp(a, b) != 0)
		fail = 1;
	free(b);
}

ຈຳນວນເຕັມ
main(void)
{
	test("");
	test("a");
	test("\0");
	test("abcdefghijklmnopqrstuvwxyz");
	ສົ່ງຄືນ fail;
}
