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

#అన్తర్భావ "includes.h"
#నిర్వచితం_కాకపోతే HAVE_TIMINGSAFE_BCMP

పూర్ణాంకం
timingsafe_bcmp(స్థిరరాశి శూన్య *b1, స్థిరరాశి శూన్య *b2, కొలత_t n)
{
	స్థిరరాశి గుర్తులేని అక్షరం *p1 = b1, *p2 = b2;
	పూర్ణాంకం ret = 0;

	కొరకు (; n > 0; n--)
		ret |= *p1++ ^ *p2++;
	తిరిగి (ret != 0);
}

#అయితే_ముగింపు /* TIMINGSAFE_BCMP */
