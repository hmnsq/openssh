/*
 * Copyright (c) 2019 Darren Tucker
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

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#घोषणा TMPFILE "utimensat.tmp"
#घोषणा TMPFILE2 "utimensat.tmp2"

#अगर_अघोषित AT_SYMLINK_NOFOLLOW
# define AT_SYMLINK_NOFOLLOW 0x80000000
#पूर्ण_अगर

पूर्णांक utimensat(पूर्णांक, स्थिर अक्षर *, स्थिर काष्ठा timespec[2], पूर्णांक);

अटल व्योम
cleanup(व्योम)
{
	(व्योम)unlink(TMPFILE);
	(व्योम)unlink(TMPFILE2);
}

अटल व्योम
fail(अक्षर *संदेश, दीर्घ expect, दीर्घ got)
{
	पूर्णांक saved_errno = त्रुटि_सं;

	अगर (expect == got && got == 0)
		ख_लिखो(मानक_त्रुटि, "utimensat: %s: %s\n", संदेश,
		     म_त्रुटि(saved_errno));
	अन्यथा
		ख_लिखो(मानक_त्रुटि, "utimensat: %s: expected %ld got %ld\n",
		     संदेश, expect, got);
	cleanup();
	निकास(1);
}

पूर्णांक
मुख्य(व्योम)
{
	पूर्णांक fd;
	काष्ठा stat sb;
	काष्ठा timespec ts[2];

	cleanup();
	अगर ((fd = खोलो(TMPFILE, O_CREAT, 0600)) == -1)
		fail("open", 0, 0);
	बंद(fd);

	ts[0].tv_sec = 12345678;
	ts[0].tv_nsec = 23456789;
	ts[1].tv_sec = 34567890;
	ts[1].tv_nsec = 45678901;
	अगर (utimensat(AT_FDCWD, TMPFILE, ts, AT_SYMLINK_NOFOLLOW) == -1)
		fail("utimensat", 0, 0);

	अगर (stat(TMPFILE, &sb) == -1)
		fail("stat", 0, 0);
#अगर 0
	/*
	 * This test only works on filesystems mounted 'noatime', otherwise the
	 * stat() above resets atime. Skip by default.
	 */
	अगर (sb.st_atime != 12345678)
		fail("st_atime", 0, 0);
#पूर्ण_अगर
	अगर (sb.st_mtime != 34567890)
		fail("st_mtime", 0, 0);
#अगर 0
	/*
	 * Results expected to be rounded to the nearest microsecond.
	 * Depends on timestamp precision in kernel and filesystem so
	 * disabled by default.
	 */
	अगर (sb.st_atim.tv_nsec != 23456000)
		fail("atim.tv_nsec", 23456000, sb.st_atim.tv_nsec);
	अगर (sb.st_mtim.tv_nsec != 45678000)
		fail("mtim.tv_nsec", 45678000, sb.st_mtim.tv_nsec);
#पूर्ण_अगर

	/*
	 * POSIX specifies that when given a symlink, AT_SYMLINK_NOFOLLOW
	 * should update the symlink and not the destination.  The compat
	 * code doesn't have a way to do this, so where possible it fails
	 * with instead of following a symlink when explicitly asked not to.
	 * Here we just test that it does not update the destination.
	 */
	अगर (नाम(TMPFILE, TMPFILE2) == -1)
		fail("rename", 0, 0);
	अगर (symlink(TMPFILE2, TMPFILE) == -1)
		fail("symlink", 0, 0);
	ts[0].tv_sec = 11223344;
	ts[1].tv_sec = 55667788;
	(व्योम)utimensat(AT_FDCWD, TMPFILE, ts, AT_SYMLINK_NOFOLLOW);
	अगर (stat(TMPFILE2, &sb) == -1)
		fail("stat", 0, 0 );
	अगर (sb.st_atime == 11223344)
		fail("utimensat symlink st_atime", 0, 0 );
	अगर (sb.st_mtime == 55667788)
		fail("utimensat symlink st_mtime", 0, 0 );

	cleanup();
	निकास(0);
}
