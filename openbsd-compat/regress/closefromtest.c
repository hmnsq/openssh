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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਅੰਕ_OPENS 10

ਖਾਲੀ
fail(ਅੱਖਰ *ਸੁਨੇਹਾ)
{
	fprintf(stderr, "closefrom: %s\n", ਸੁਨੇਹਾ);
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਪੂਰਨ
ਮੁੱਖ(ਖਾਲੀ)
{
	ਪੂਰਨ i, max, fds[ਅੰਕ_OPENS];
	ਅੱਖਰ buf[512];

	ਲਈ (i = 0; i < ਅੰਕ_OPENS; i++)
		ਜੇ ((fds[i] = open("/dev/null", O_RDONLY)) == -1)
			ਬਾਹਰ_ਨਿਕਲੋ(0);	/* can't test */
	max = i - 1;

	/* should close last fd only */
	closefrom(fds[max]);
	ਜੇ (close(fds[max]) != -1)
		fail("failed to close highest fd");

	/* make sure we can still use remaining descriptors */
	ਲਈ (i = 0; i < max; i++)
		ਜੇ (ਪਠ(fds[i], buf, ਆਕਾਰ(buf)) == -1)
			fail("closed descriptors it should not have");

	/* should close all fds */
	closefrom(fds[0]);
	ਲਈ (i = 0; i < ਅੰਕ_OPENS; i++)
		ਜੇ (close(fds[i]) != -1)
			fail("failed to close from lowest fd");
	ਵਾਪਸ 0;
}
