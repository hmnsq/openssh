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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>

#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <unistd.h>

#నిర్వచించు అంకె_OPENS 10

శూన్య
fail(అక్షరం *సందేశం)
{
	fprintf(stderr, "closefrom: %s\n", సందేశం);
	నిష్క్రమించు(1);
}

పూర్ణాంకం
ప్రధాన(శూన్య)
{
	పూర్ణాంకం i, max, fds[అంకె_OPENS];
	అక్షరం buf[512];

	కొరకు (i = 0; i < అంకె_OPENS; i++)
		ఒకవేళ ((fds[i] = open("/dev/null", O_RDONLY)) == -1)
			నిష్క్రమించు(0);	/* can't test */
	max = i - 1;

	/* should close last fd only */
	closefrom(fds[max]);
	ఒకవేళ (close(fds[max]) != -1)
		fail("failed to close highest fd");

	/* make sure we can still use remaining descriptors */
	కొరకు (i = 0; i < max; i++)
		ఒకవేళ (పఠ(fds[i], buf, పరిమాణం(buf)) == -1)
			fail("closed descriptors it should not have");

	/* should close all fds */
	closefrom(fds[0]);
	కొరకు (i = 0; i < అంకె_OPENS; i++)
		ఒకవేళ (close(fds[i]) != -1)
			fail("failed to close from lowest fd");
	తిరిగి 0;
}
