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

#అన్తర్భావ <sys/time.h>

#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <time.h>

పూర్ణాంకం
ప్రధాన(శూన్య)
{
	నిర్మాణం timeval tv;
	నిర్మాణం tm *tm;
	అక్షరం buf[1024];

	ఒకవేళ (gettimeofday(&tv, ఖాళీ) != 0)
		నిష్క్రమించు(1);
	ఒకవేళ ((tm = localtime(&tv.tv_sec)) == ఖాళీ)
		నిష్క్రమించు(2);
	ఒకవేళ (strftime(buf, పరిమాణం buf, "%Y%m%dT%H%M%S", tm) <= 0)
		నిష్క్రమించు(3);
	రాయి("%s.%06d\n", buf, (పూర్ణాంకం)tv.tv_usec);
	నిష్క్రమించు(0);
}
