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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>

#समावेश <fcntl.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <unistd.h>

#घोषणा अंक_OPENS 10

व्योम
fail(अक्षर *संदेश)
{
	ख_लिखो(मानक_त्रुटि, "closefrom: %s\n", संदेश);
	निकास(1);
}

पूर्णांक
मुख्य(व्योम)
{
	पूर्णांक i, max, fds[अंक_OPENS];
	अक्षर buf[512];

	क्रम (i = 0; i < अंक_OPENS; i++)
		अगर ((fds[i] = खोलो("/dev/null", O_RDONLY)) == -1)
			निकास(0);	/* can't test */
	max = i - 1;

	/* should close last fd only */
	closefrom(fds[max]);
	अगर (बंद(fds[max]) != -1)
		fail("failed to close highest fd");

	/* make sure we can still use remaining descriptors */
	क्रम (i = 0; i < max; i++)
		अगर (पढ़ो(fds[i], buf, माप(buf)) == -1)
			fail("closed descriptors it should not have");

	/* should close all fds */
	closefrom(fds[0]);
	क्रम (i = 0; i < अंक_OPENS; i++)
		अगर (बंद(fds[i]) != -1)
			fail("failed to close from lowest fd");
	वापस 0;
}
