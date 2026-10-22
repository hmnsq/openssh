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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ವ್ಯಾಖ್ಯಾನಿಸು ಅಂಕೆ_OPENS 10

ಶೂನ್ಯ
fail(ಅಕ್ಷರ *ಸಂದೇಶ)
{
	fprintf(stderr, "closefrom: %s\n", ಸಂದೇಶ);
	ನಿರ್ಗಮಿಸು(1);
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ i, max, fds[ಅಂಕೆ_OPENS];
	ಅಕ್ಷರ buf[512];

	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_OPENS; i++)
		ಆದರೆ ((fds[i] = open("/dev/null", O_RDONLY)) == -1)
			ನಿರ್ಗಮಿಸು(0);	/* can't test */
	max = i - 1;

	/* should close last fd only */
	closefrom(fds[max]);
	ಆದರೆ (close(fds[max]) != -1)
		fail("failed to close highest fd");

	/* make sure we can still use remaining descriptors */
	ಗಾಗಿ (i = 0; i < max; i++)
		ಆದರೆ (ಪಠ(fds[i], buf, ಗಾತ್ರ(buf)) == -1)
			fail("closed descriptors it should not have");

	/* should close all fds */
	closefrom(fds[0]);
	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_OPENS; i++)
		ಆದರೆ (close(fds[i]) != -1)
			fail("failed to close from lowest fd");
	ಹಿಂತಿರುಗಿ 0;
}
