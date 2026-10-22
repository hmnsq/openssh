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

#অন্তর্ভাব <sys/time.h>

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <time.h>

পূর্ণাঙ্ক
main(শূন্য)
{
	সংরচনা timeval tv;
	সংরচনা tm *tm;
	বর্ণ buf[1024];

	যদি (gettimeofday(&tv, রিক্ত) != 0)
		exit(1);
	যদি ((tm = localtime(&tv.tv_sec)) == রিক্ত)
		exit(2);
	যদি (strftime(buf, পরিমাণ buf, "%Y%m%dT%H%M%S", tm) <= 0)
		exit(3);
	printf("%s.%06d\n", buf, (পূর্ণাঙ্ক)tv.tv_usec);
	exit(0);
}
