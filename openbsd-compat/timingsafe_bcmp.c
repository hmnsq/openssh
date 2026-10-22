/*	$OpenBSD: timingsafe_bcmp.c,v 1.1 2010/09/24 13:33:00 matthew Exp $	*/
/*
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
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

/* OPENBSD ORIGINAL: lib/libc/string/timingsafe_bcmp.c */

#अन्तर्भाव "includes.h"
#ifndef HAVE_TIMINGSAFE_BCMP

पूर्णांक
timingsafe_bcmp(स्थिरांक शून्य *b1, स्थिरांक शून्य *b2, माप_प्रकार n)
{
	स्थिरांक अचिन्हित अक्षर *p1 = b1, *p2 = b2;
	पूर्णांक ret = 0;

	साठी (; n > 0; n--)
		ret |= *p1++ ^ *p2++;
	परत (ret != 0);
}

#endif /* TIMINGSAFE_BCMP */
