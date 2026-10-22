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

#અન્તર્ભાવ "includes.h"
#ifndef HAVE_TIMINGSAFE_BCMP

પૂર્ણાંક
timingsafe_bcmp(અચલ શૂન્ય *b1, અચલ શૂન્ય *b2, size_t n)
{
	અચલ unsigned અક્ષર *p1 = b1, *p2 = b2;
	પૂર્ણાંક ret = 0;

	માટે (; n > 0; n--)
		ret |= *p1++ ^ *p2++;
	પાછા (ret != 0);
}

#endif /* TIMINGSAFE_BCMP */
