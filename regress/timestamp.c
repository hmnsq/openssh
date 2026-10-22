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

#समावेश <sys/time.h>

#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <time.h>

पूर्णांक
मुख्य(व्योम)
{
	काष्ठा timeval tv;
	काष्ठा पंचांग *पंचांग;
	अक्षर buf[1024];

	अगर (gettimeofday(&tv, शून्य) != 0)
		निकास(1);
	अगर ((पंचांग = स_स्थानीय(&tv.tv_sec)) == शून्य)
		निकास(2);
	अगर (स_माला(buf, माप buf, "%Y%m%dT%H%M%S", पंचांग) <= 0)
		निकास(3);
	म_लिखो("%s.%06d\n", buf, (पूर्णांक)tv.tv_usec);
	निकास(0);
}
