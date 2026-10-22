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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#define TMPFILE "utimensat.tmp"
#define TMPFILE2 "utimensat.tmp2"

#ifndef AT_SYMLINK_NOFOLLOW
# define AT_SYMLINK_NOFOLLOW 0x80000000
#endif

ಪೂರ್ಣಾಙ್ಕ utimensat(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ಸಂರಚನಾ timespec[2], ಪೂರ್ಣಾಙ್ಕ);

ಸ್ಥಿರ ಶೂನ್ಯ
cleanup(ಶೂನ್ಯ)
{
	(ಶೂನ್ಯ)unlink(TMPFILE);
	(ಶೂನ್ಯ)unlink(TMPFILE2);
}

ಸ್ಥಿರ ಶೂನ್ಯ
fail(ವರ್ಣ *ಸಂದೇಶ, long expect, long got)
{
	ಪೂರ್ಣಾಙ್ಕ saved_errno = errno;

	ಯದಿ (expect == got && got == 0)
		fprintf(stderr, "utimensat: %s: %s\n", ಸಂದೇಶ,
		     strerror(saved_errno));
	ಅನ್ಯಥಾ
		fprintf(stderr, "utimensat: %s: expected %ld got %ld\n",
		     ಸಂದೇಶ, expect, got);
	cleanup();
	exit(1);
}

ಪೂರ್ಣಾಙ್ಕ
main(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ fd;
	ಸಂರಚನಾ stat sb;
	ಸಂರಚನಾ timespec ts[2];

	cleanup();
	ಯದಿ ((fd = open(TMPFILE, O_CREAT, 0600)) == -1)
		fail("open", 0, 0);
	close(fd);

	ts[0].tv_sec = 12345678;
	ts[0].tv_nsec = 23456789;
	ts[1].tv_sec = 34567890;
	ts[1].tv_nsec = 45678901;
	ಯದಿ (utimensat(AT_FDCWD, TMPFILE, ts, AT_SYMLINK_NOFOLLOW) == -1)
		fail("utimensat", 0, 0);

	ಯದಿ (stat(TMPFILE, &sb) == -1)
		fail("stat", 0, 0);
#ಯದಿ 0
	/*
	 * This test only works on filesystems mounted 'noatime', otherwise the
	 * stat() above resets atime. Skip by default.
	 */
	ಯದಿ (sb.st_atime != 12345678)
		fail("st_atime", 0, 0);
#endif
	ಯದಿ (sb.st_mtime != 34567890)
		fail("st_mtime", 0, 0);
#ಯದಿ 0
	/*
	 * Results expected to be rounded to the nearest microsecond.
	 * Depends on timestamp precision in kernel and filesystem so
	 * disabled by default.
	 */
	ಯದಿ (sb.st_atim.tv_nsec != 23456000)
		fail("atim.tv_nsec", 23456000, sb.st_atim.tv_nsec);
	ಯದಿ (sb.st_mtim.tv_nsec != 45678000)
		fail("mtim.tv_nsec", 45678000, sb.st_mtim.tv_nsec);
#endif

	/*
	 * POSIX specifies that when given a symlink, AT_SYMLINK_NOFOLLOW
	 * should update the symlink and not the destination.  The compat
	 * code doesn't have a way to do this, so where possible it fails
	 * with instead of following a symlink when explicitly asked not to.
	 * Here we just test that it does not update the destination.
	 */
	ಯದಿ (rename(TMPFILE, TMPFILE2) == -1)
		fail("rename", 0, 0);
	ಯದಿ (symlink(TMPFILE2, TMPFILE) == -1)
		fail("symlink", 0, 0);
	ts[0].tv_sec = 11223344;
	ts[1].tv_sec = 55667788;
	(ಶೂನ್ಯ)utimensat(AT_FDCWD, TMPFILE, ts, AT_SYMLINK_NOFOLLOW);
	ಯದಿ (stat(TMPFILE2, &sb) == -1)
		fail("stat", 0, 0 );
	ಯದಿ (sb.st_atime == 11223344)
		fail("utimensat symlink st_atime", 0, 0 );
	ಯದಿ (sb.st_mtime == 55667788)
		fail("utimensat symlink st_mtime", 0, 0 );

	cleanup();
	exit(0);
}
