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

#ಅನ್ತರ್ಭಾವ <sys/time.h>

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <time.h>

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಶೂನ್ಯ)
{
	ರಚನೆ timeval tv;
	ರಚನೆ tm *tm;
	ಅಕ್ಷರ buf[1024];

	ಆದರೆ (gettimeofday(&tv, ಖಾಲಿ) != 0)
		ನಿರ್ಗಮಿಸು(1);
	ಆದರೆ ((tm = localtime(&tv.tv_sec)) == ಖಾಲಿ)
		ನಿರ್ಗಮಿಸು(2);
	ಆದರೆ (strftime(buf, ಗಾತ್ರ buf, "%Y%m%dT%H%M%S", tm) <= 0)
		ನಿರ್ಗಮಿಸು(3);
	ಬರೆ("%s.%06d\n", buf, (ಪೂರ್ಣಾಂಕ)tv.tv_usec);
	ನಿರ್ಗಮಿಸು(0);
}
