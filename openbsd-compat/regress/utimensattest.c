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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#define TMPFILE "utimensat.tmp"
#define TMPFILE2 "utimensat.tmp2"

#ifndef AT_SYMLINK_NOFOLLOW
# define AT_SYMLINK_NOFOLLOW 0x80000000
#endif

પૂર્ણાંક utimensat(પૂર્ણાંક, અચલ અક્ષર *, અચલ સંરચના timespec[2], પૂર્ણાંક);

સ્થિર શૂન્ય
cleanup(શૂન્ય)
{
	(શૂન્ય)unlink(TMPFILE);
	(શૂન્ય)unlink(TMPFILE2);
}

સ્થિર શૂન્ય
fail(અક્ષર *સંદેશ, long expect, long got)
{
	પૂર્ણાંક saved_errno = errno;

	જો (expect == got && got == 0)
		fprintf(stderr, "utimensat: %s: %s\n", સંદેશ,
		     strerror(saved_errno));
	નહીંતર
		fprintf(stderr, "utimensat: %s: expected %ld got %ld\n",
		     સંદેશ, expect, got);
	cleanup();
	exit(1);
}

પૂર્ણાંક
મુખ્ય(શૂન્ય)
{
	પૂર્ણાંક fd;
	સંરચના stat sb;
	સંરચના timespec ts[2];

	cleanup();
	જો ((fd = open(TMPFILE, O_CREAT, 0600)) == -1)
		fail("open", 0, 0);
	close(fd);

	ts[0].tv_sec = 12345678;
	ts[0].tv_nsec = 23456789;
	ts[1].tv_sec = 34567890;
	ts[1].tv_nsec = 45678901;
	જો (utimensat(AT_FDCWD, TMPFILE, ts, AT_SYMLINK_NOFOLLOW) == -1)
		fail("utimensat", 0, 0);

	જો (stat(TMPFILE, &sb) == -1)
		fail("stat", 0, 0);
#જો 0
	/*
	 * This test only works on filesystems mounted 'noatime', otherwise the
	 * stat() above resets atime. Skip by default.
	 */
	જો (sb.st_atime != 12345678)
		fail("st_atime", 0, 0);
#endif
	જો (sb.st_mtime != 34567890)
		fail("st_mtime", 0, 0);
#જો 0
	/*
	 * Results expected to be rounded to the nearest microsecond.
	 * Depends on timestamp precision in kernel and filesystem so
	 * disabled by default.
	 */
	જો (sb.st_atim.tv_nsec != 23456000)
		fail("atim.tv_nsec", 23456000, sb.st_atim.tv_nsec);
	જો (sb.st_mtim.tv_nsec != 45678000)
		fail("mtim.tv_nsec", 45678000, sb.st_mtim.tv_nsec);
#endif

	/*
	 * POSIX specifies that when given a symlink, AT_SYMLINK_NOFOLLOW
	 * should update the symlink and not the destination.  The compat
	 * code doesn't have a way to do this, so where possible it fails
	 * with instead of following a symlink when explicitly asked not to.
	 * Here we just test that it does not update the destination.
	 */
	જો (rename(TMPFILE, TMPFILE2) == -1)
		fail("rename", 0, 0);
	જો (symlink(TMPFILE2, TMPFILE) == -1)
		fail("symlink", 0, 0);
	ts[0].tv_sec = 11223344;
	ts[1].tv_sec = 55667788;
	(શૂન્ય)utimensat(AT_FDCWD, TMPFILE, ts, AT_SYMLINK_NOFOLLOW);
	જો (stat(TMPFILE2, &sb) == -1)
		fail("stat", 0, 0 );
	જો (sb.st_atime == 11223344)
		fail("utimensat symlink st_atime", 0, 0 );
	જો (sb.st_mtime == 55667788)
		fail("utimensat symlink st_mtime", 0, 0 );

	cleanup();
	exit(0);
}
