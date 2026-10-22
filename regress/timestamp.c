/*
 * Copyright (c) 2023 Darren Tucker <dtucker@openssh.com>
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

/* $OpenBSD: timestamp.c,v 1.1 2023/03/01 09:29:32 dtucker Exp $ */

/*
 * Print a microsecond-granularity timestamp to stdout in an ISO8601-ish
 * format, which we can then use as the first component of the log file
 * so that they'll sort into chronological order.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>

ਪੂਰਨ
ਮੁੱਖ(ਖਾਲੀ)
{
	ਬਣਤਰ timeval tv;
	ਬਣਤਰ tm *tm;
	ਅੱਖਰ buf[1024];

	ਜੇ (gettimeofday(&tv, ਨਿਰਾ) != 0)
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	ਜੇ ((tm = localtime(&tv.tv_sec)) == ਨਿਰਾ)
		ਬਾਹਰ_ਨਿਕਲੋ(2);
	ਜੇ (strftime(buf, ਆਕਾਰ buf, "%Y%m%dT%H%M%S", tm) <= 0)
		ਬਾਹਰ_ਨਿਕਲੋ(3);
	ਲਿਖੋ("%s.%06d\n", buf, (ਪੂਰਨ)tv.tv_usec);
	ਬਾਹਰ_ਨਿਕਲੋ(0);
}
