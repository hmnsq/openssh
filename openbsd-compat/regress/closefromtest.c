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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>

#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <unistd.h>

#define இலக்கம்_OPENS 10

வெறுமை
fail(எழுத்து *செய்தி)
{
	fprintf(stderr, "closefrom: %s\n", செய்தி);
	exit(1);
}

முழு
முதன்மை(வெறுமை)
{
	முழு i, max, fds[இலக்கம்_OPENS];
	எழுத்து buf[512];

	க்கு (i = 0; i < இலக்கம்_OPENS; i++)
		எனில் ((fds[i] = open("/dev/null", O_RDONLY)) == -1)
			exit(0);	/* can't test */
	max = i - 1;

	/* should close last fd only */
	closefrom(fds[max]);
	எனில் (close(fds[max]) != -1)
		fail("failed to close highest fd");

	/* make sure we can still use remaining descriptors */
	க்கு (i = 0; i < max; i++)
		எனில் (பட(fds[i], buf, அளவு(buf)) == -1)
			fail("closed descriptors it should not have");

	/* should close all fds */
	closefrom(fds[0]);
	க்கு (i = 0; i < இலக்கம்_OPENS; i++)
		எனில் (close(fds[i]) != -1)
			fail("failed to close from lowest fd");
	திரும்பு 0;
}
