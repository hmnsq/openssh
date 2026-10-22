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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#నిర్వచించు TMPFILE "utimensat.tmp"
#నిర్వచించు TMPFILE2 "utimensat.tmp2"

#నిర్వచితం_కాకపోతే AT_SYMLINK_NOFOLLOW
# define AT_SYMLINK_NOFOLLOW 0x80000000
#అయితే_ముగింపు

పూర్ణాంకం utimensat(పూర్ణాంకం, స్థిరరాశి అక్షరం *, స్థిరరాశి నిర్మాణం timespec[2], పూర్ణాంకం);

స్థిర శూన్య
cleanup(శూన్య)
{
	(శూన్య)unlink(TMPFILE);
	(శూన్య)unlink(TMPFILE2);
}

స్థిర శూన్య
fail(అక్షరం *సందేశం, దీర్ఘ expect, దీర్ఘ got)
{
	పూర్ణాంకం saved_errno = errno;

	ఒకవేళ (expect == got && got == 0)
		fprintf(stderr, "utimensat: %s: %s\n", సందేశం,
		     strerror(saved_errno));
	లేకపోతే
		fprintf(stderr, "utimensat: %s: expected %ld got %ld\n",
		     సందేశం, expect, got);
	cleanup();
	నిష్క్రమించు(1);
}

పూర్ణాంకం
ప్రధాన(శూన్య)
{
	పూర్ణాంకం fd;
	నిర్మాణం stat sb;
	నిర్మాణం timespec ts[2];

	cleanup();
	ఒకవేళ ((fd = open(TMPFILE, O_CREAT, 0600)) == -1)
		fail("open", 0, 0);
	close(fd);

	ts[0].tv_sec = 12345678;
	ts[0].tv_nsec = 23456789;
	ts[1].tv_sec = 34567890;
	ts[1].tv_nsec = 45678901;
	ఒకవేళ (utimensat(AT_FDCWD, TMPFILE, ts, AT_SYMLINK_NOFOLLOW) == -1)
		fail("utimensat", 0, 0);

	ఒకవేళ (stat(TMPFILE, &sb) == -1)
		fail("stat", 0, 0);
#ఒకవేళ 0
	/*
	 * This test only works on filesystems mounted 'noatime', otherwise the
	 * stat() above resets atime. Skip by default.
	 */
	ఒకవేళ (sb.st_atime != 12345678)
		fail("st_atime", 0, 0);
#అయితే_ముగింపు
	ఒకవేళ (sb.st_mtime != 34567890)
		fail("st_mtime", 0, 0);
#ఒకవేళ 0
	/*
	 * Results expected to be rounded to the nearest microsecond.
	 * Depends on timestamp precision in kernel and filesystem so
	 * disabled by default.
	 */
	ఒకవేళ (sb.st_atim.tv_nsec != 23456000)
		fail("atim.tv_nsec", 23456000, sb.st_atim.tv_nsec);
	ఒకవేళ (sb.st_mtim.tv_nsec != 45678000)
		fail("mtim.tv_nsec", 45678000, sb.st_mtim.tv_nsec);
#అయితే_ముగింపు

	/*
	 * POSIX specifies that when given a symlink, AT_SYMLINK_NOFOLLOW
	 * should update the symlink and not the destination.  The compat
	 * code doesn't have a way to do this, so where possible it fails
	 * with instead of following a symlink when explicitly asked not to.
	 * Here we just test that it does not update the destination.
	 */
	ఒకవేళ (rename(TMPFILE, TMPFILE2) == -1)
		fail("rename", 0, 0);
	ఒకవేళ (symlink(TMPFILE2, TMPFILE) == -1)
		fail("symlink", 0, 0);
	ts[0].tv_sec = 11223344;
	ts[1].tv_sec = 55667788;
	(శూన్య)utimensat(AT_FDCWD, TMPFILE, ts, AT_SYMLINK_NOFOLLOW);
	ఒకవేళ (stat(TMPFILE2, &sb) == -1)
		fail("stat", 0, 0 );
	ఒకవేళ (sb.st_atime == 11223344)
		fail("utimensat symlink st_atime", 0, 0 );
	ఒకవేళ (sb.st_mtime == 55667788)
		fail("utimensat symlink st_mtime", 0, 0 );

	cleanup();
	నిష్క్రమించు(0);
}
