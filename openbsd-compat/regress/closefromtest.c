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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>

#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <unistd.h>

#define അക്കം_OPENS 10

ശൂന്യം
fail(അക്ഷരം *സന്ദേശം)
{
	fprintf(stderr, "closefrom: %s\n", സന്ദേശം);
	exit(1);
}

പൂർണ്ണസംഖ്യ
പ്രധാന(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ i, max, fds[അക്കം_OPENS];
	അക്ഷരം buf[512];

	വേണ്ടി (i = 0; i < അക്കം_OPENS; i++)
		എങ്കിൽ ((fds[i] = open("/dev/null", O_RDONLY)) == -1)
			exit(0);	/* can't test */
	max = i - 1;

	/* should close last fd only */
	closefrom(fds[max]);
	എങ്കിൽ (close(fds[max]) != -1)
		fail("failed to close highest fd");

	/* make sure we can still use remaining descriptors */
	വേണ്ടി (i = 0; i < max; i++)
		എങ്കിൽ (പഠ(fds[i], buf, വലുപ്പം(buf)) == -1)
			fail("closed descriptors it should not have");

	/* should close all fds */
	closefrom(fds[0]);
	വേണ്ടി (i = 0; i < അക്കം_OPENS; i++)
		എങ്കിൽ (close(fds[i]) != -1)
			fail("failed to close from lowest fd");
	തിരികെ 0;
}
