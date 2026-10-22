/*
 * Copyright (c) 2006 Darren Tucker
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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>

#شامل <fcntl.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <unistd.h>

#define رقم_OPENS 10

تهی
fail(نویسه *پیام)
{
	fprintf(stderr, "closefrom: %s\n", پیام);
	exit(1);
}

صحیح
اصلی(تهی)
{
	صحیح i, max, fds[رقم_OPENS];
	نویسه buf[512];

	برای (i = 0; i < رقم_OPENS; i++)
		اگر ((fds[i] = open("/dev/null", O_RDONLY)) == -1)
			exit(0);	/* can't test */
	max = i - 1;

	/* should close last fd only */
	closefrom(fds[max]);
	اگر (close(fds[max]) != -1)
		fail("failed to close highest fd");

	/* make sure we can still use remaining descriptors */
	برای (i = 0; i < max; i++)
		اگر (اقرأ(fds[i], buf, اندازه(buf)) == -1)
			fail("closed descriptors it should not have");

	/* should close all fds */
	closefrom(fds[0]);
	برای (i = 0; i < رقم_OPENS; i++)
		اگر (close(fds[i]) != -1)
			fail("failed to close from lowest fd");
	بازگشت 0;
}
