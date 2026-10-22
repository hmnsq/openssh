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

ಪೂರ್ಣಾಙ್ಕ
main(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ timeval tv;
	ಸಂರಚನಾ tm *tm;
	ವರ್ಣ buf[1024];

	ಯದಿ (gettimeofday(&tv, ರಿಕ್ತ) != 0)
		exit(1);
	ಯದಿ ((tm = localtime(&tv.tv_sec)) == ರಿಕ್ತ)
		exit(2);
	ಯದಿ (strftime(buf, ಪರಿಮಾಣ buf, "%Y%m%dT%H%M%S", tm) <= 0)
		exit(3);
	printf("%s.%06d\n", buf, (ಪೂರ್ಣಾಙ್ಕ)tv.tv_usec);
	exit(0);
}
