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

#تعریف_کرو عدد_OPENS 10

خالی
fail(حرف *پیغام)
{
	fprintf(stderr, "closefrom: %s\n", پیغام);
	باہر_نکلو(1);
}

صحیح
مین(خالی)
{
	صحیح i, max, fds[عدد_OPENS];
	حرف buf[512];

	برائے (i = 0; i < عدد_OPENS; i++)
		اگر ((fds[i] = open("/dev/null", O_RDONLY)) == -1)
			باہر_نکلو(0);	/* can't test */
	max = i - 1;

	/* should close last fd only */
	closefrom(fds[max]);
	اگر (close(fds[max]) != -1)
		fail("failed to close highest fd");

	/* make sure we can still use remaining descriptors */
	برائے (i = 0; i < max; i++)
		اگر (اقرأ(fds[i], buf, حجم(buf)) == -1)
			fail("closed descriptors it should not have");

	/* should close all fds */
	closefrom(fds[0]);
	برائے (i = 0; i < عدد_OPENS; i++)
		اگر (close(fds[i]) != -1)
			fail("failed to close from lowest fd");
	واپس 0;
}
