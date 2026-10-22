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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

സ്ഥിതം പൂർണ്ണസംഖ്യ fail = 0;

ശൂന്യം
test(സ്ഥിരം അക്ഷരം *a)
{
	അക്ഷരം *b;

	b = strdup(a);
	എങ്കിൽ (b == 0) {
		fail = 1;
		തിരികെ;
	}
	എങ്കിൽ (strcmp(a, b) != 0)
		fail = 1;
	സ്വതന്ത്രം(b);
}

പൂർണ്ണസംഖ്യ
പ്രധാന(ശൂന്യം)
{
	test("");
	test("a");
	test("\0");
	test("abcdefghijklmnopqrstuvwxyz");
	തിരികെ fail;
}
