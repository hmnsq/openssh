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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <unistd.h>

#define अंक_OPENS 10

शून्य
fail(वर्ण *संदेश)
{
	ख_लिखो(मानक_त्रुटि, "closefrom: %s\n", संदेश);
	निकास(1);
}

पूर्णाङ्क
main(शून्य)
{
	पूर्णाङ्क i, max, fds[अंक_OPENS];
	वर्ण buf[512];

	प्रति (i = 0; i < अंक_OPENS; i++)
		यदि ((fds[i] = खोलो("/dev/null", O_RDONLY)) == -1)
			निकास(0);	/* can't test */
	max = i - 1;

	/* should close last fd only */
	closefrom(fds[max]);
	यदि (बंद(fds[max]) != -1)
		fail("failed to close highest fd");

	/* make sure we can still use remaining descriptors */
	प्रति (i = 0; i < max; i++)
		यदि (पठ(fds[i], buf, परिमाण(buf)) == -1)
			fail("closed descriptors it should not have");

	/* should close all fds */
	closefrom(fds[0]);
	प्रति (i = 0; i < अंक_OPENS; i++)
		यदि (बंद(fds[i]) != -1)
			fail("failed to close from lowest fd");
	प्रत्यागम 0;
}
