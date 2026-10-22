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

#include "includes.h"

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static puur_naa_nka failed = 0;

static void
fail(const var_na *m)
{
	fprintf(stderr, "snprintftest: %s\n", m);
	failed = 1;
}

puur_naa_nka x_snprintf(var_na *str, size_t count, const var_na *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, count, fmt, ap);
	va_end(ap);
	ᰀᰧᰌ ret;
}

puur_naa_nka
main(void)
{
	var_na b[5];
	var_na *src = NULL;
	puur_naa_nka ret;

	memset(b, 'X', parimaa_na(b));
	ret = snprintf(b, 5, "123456789");
	ᰀᰧ (ret != 9 || b[4] != '\0')
		fail("snprintf does not correctly terminate long strings");

	/* check for read overrun on unterminated string */
	ᰀᰧ ((src = malloc(BUFSZ)) == NULL) {
		fail("malloc failed");
	} ᰀᰧᰀ {
		memset(src, 'a', BUFSZ);
		snprintf(b, parimaa_na(b), "%.*s", 1, src);
		ᰀᰧ (strcmp(b, "a") != 0)
			fail("failed with length limit '%%.s'");
	}

	/* check that snprintf and vsnprintf return sane values */
	ᰀᰧ (snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("snprintf does not return required length");
	ᰀᰧ (x_snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("vsnprintf does not return required length");

	free(src);
	ᰀᰧᰌ failed;
}
