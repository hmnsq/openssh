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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#define TMPFILE "utimensat.tmp"
#define TMPFILE2 "utimensat.tmp2"

#ifndef AT_SYMLINK_NOFOLLOW
# define AT_SYMLINK_NOFOLLOW 0x80000000
#endif

पूर्णाङ्क utimensat(पूर्णाङ्क, ध्रुव वर्ण *, ध्रुव संरचना timespec[2], पूर्णाङ्क);

स्थिर शून्य
cleanup(शून्य)
{
	(शून्य)unlink(TMPFILE);
	(शून्य)unlink(TMPFILE2);
}

स्थिर शून्य
fail(वर्ण *सन्देशः, long expect, long got)
{
	पूर्णाङ्क saved_errno = errno;

	सचे (expect == got && got == 0)
		fprintf(stderr, "utimensat: %s: %s\n", सन्देशः,
		     strerror(saved_errno));
	अञ्ञथा
		fprintf(stderr, "utimensat: %s: expected %ld got %ld\n",
		     सन्देशः, expect, got);
	cleanup();
	exit(1);
}

पूर्णाङ्क
main(शून्य)
{
	पूर्णाङ्क fd;
	संरचना stat sb;
	संरचना timespec ts[2];

	cleanup();
	सचे ((fd = open(TMPFILE, O_CREAT, 0600)) == -1)
		fail("open", 0, 0);
	close(fd);

	ts[0].tv_sec = 12345678;
	ts[0].tv_nsec = 23456789;
	ts[1].tv_sec = 34567890;
	ts[1].tv_nsec = 45678901;
	सचे (utimensat(AT_FDCWD, TMPFILE, ts, AT_SYMLINK_NOFOLLOW) == -1)
		fail("utimensat", 0, 0);

	सचे (stat(TMPFILE, &sb) == -1)
		fail("stat", 0, 0);
#सचे 0
	/*
	 * This test only works on filesystems mounted 'noatime', otherwise the
	 * stat() above resets atime. Skip by default.
	 */
	सचे (sb.st_atime != 12345678)
		fail("st_atime", 0, 0);
#endif
	सचे (sb.st_mtime != 34567890)
		fail("st_mtime", 0, 0);
#सचे 0
	/*
	 * Results expected to be rounded to the nearest microsecond.
	 * Depends on timestamp precision in kernel and filesystem so
	 * disabled by default.
	 */
	सचे (sb.st_atim.tv_nsec != 23456000)
		fail("atim.tv_nsec", 23456000, sb.st_atim.tv_nsec);
	सचे (sb.st_mtim.tv_nsec != 45678000)
		fail("mtim.tv_nsec", 45678000, sb.st_mtim.tv_nsec);
#endif

	/*
	 * POSIX specifies that when given a symlink, AT_SYMLINK_NOFOLLOW
	 * should update the symlink and not the destination.  The compat
	 * code doesn't have a way to do this, so where possible it fails
	 * with instead of following a symlink when explicitly asked not to.
	 * Here we just test that it does not update the destination.
	 */
	सचे (rename(TMPFILE, TMPFILE2) == -1)
		fail("rename", 0, 0);
	सचे (symlink(TMPFILE2, TMPFILE) == -1)
		fail("symlink", 0, 0);
	ts[0].tv_sec = 11223344;
	ts[1].tv_sec = 55667788;
	(शून्य)utimensat(AT_FDCWD, TMPFILE, ts, AT_SYMLINK_NOFOLLOW);
	सचे (stat(TMPFILE2, &sb) == -1)
		fail("stat", 0, 0 );
	सचे (sb.st_atime == 11223344)
		fail("utimensat symlink st_atime", 0, 0 );
	सचे (sb.st_mtime == 55667788)
		fail("utimensat symlink st_mtime", 0, 0 );

	cleanup();
	exit(0);
}
