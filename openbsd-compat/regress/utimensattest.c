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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#define TMPFILE "utimensat.tmp"
#define TMPFILE2 "utimensat.tmp2"

#ifndef AT_SYMLINK_NOFOLLOW
# define AT_SYMLINK_NOFOLLOW 0x80000000
#endif

പൂർണ്ണസംഖ്യ utimensat(പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *, സ്ഥിരം ഘടന timespec[2], പൂർണ്ണസംഖ്യ);

സ്ഥിതം ശൂന്യം
cleanup(ശൂന്യം)
{
	(ശൂന്യം)unlink(TMPFILE);
	(ശൂന്യം)unlink(TMPFILE2);
}

സ്ഥിതം ശൂന്യം
fail(അക്ഷരം *സന്ദേശം, long expect, long got)
{
	പൂർണ്ണസംഖ്യ saved_errno = errno;

	എങ്കിൽ (expect == got && got == 0)
		fprintf(stderr, "utimensat: %s: %s\n", സന്ദേശം,
		     strerror(saved_errno));
	അല്ലെങ്കിൽ
		fprintf(stderr, "utimensat: %s: expected %ld got %ld\n",
		     സന്ദേശം, expect, got);
	cleanup();
	exit(1);
}

പൂർണ്ണസംഖ്യ
പ്രധാന(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ fd;
	ഘടന stat sb;
	ഘടന timespec ts[2];

	cleanup();
	എങ്കിൽ ((fd = open(TMPFILE, O_CREAT, 0600)) == -1)
		fail("open", 0, 0);
	close(fd);

	ts[0].tv_sec = 12345678;
	ts[0].tv_nsec = 23456789;
	ts[1].tv_sec = 34567890;
	ts[1].tv_nsec = 45678901;
	എങ്കിൽ (utimensat(AT_FDCWD, TMPFILE, ts, AT_SYMLINK_NOFOLLOW) == -1)
		fail("utimensat", 0, 0);

	എങ്കിൽ (stat(TMPFILE, &sb) == -1)
		fail("stat", 0, 0);
#എങ്കിൽ 0
	/*
	 * This test only works on filesystems mounted 'noatime', otherwise the
	 * stat() above resets atime. Skip by default.
	 */
	എങ്കിൽ (sb.st_atime != 12345678)
		fail("st_atime", 0, 0);
#endif
	എങ്കിൽ (sb.st_mtime != 34567890)
		fail("st_mtime", 0, 0);
#എങ്കിൽ 0
	/*
	 * Results expected to be rounded to the nearest microsecond.
	 * Depends on timestamp precision in kernel and filesystem so
	 * disabled by default.
	 */
	എങ്കിൽ (sb.st_atim.tv_nsec != 23456000)
		fail("atim.tv_nsec", 23456000, sb.st_atim.tv_nsec);
	എങ്കിൽ (sb.st_mtim.tv_nsec != 45678000)
		fail("mtim.tv_nsec", 45678000, sb.st_mtim.tv_nsec);
#endif

	/*
	 * POSIX specifies that when given a symlink, AT_SYMLINK_NOFOLLOW
	 * should update the symlink and not the destination.  The compat
	 * code doesn't have a way to do this, so where possible it fails
	 * with instead of following a symlink when explicitly asked not to.
	 * Here we just test that it does not update the destination.
	 */
	എങ്കിൽ (rename(TMPFILE, TMPFILE2) == -1)
		fail("rename", 0, 0);
	എങ്കിൽ (symlink(TMPFILE2, TMPFILE) == -1)
		fail("symlink", 0, 0);
	ts[0].tv_sec = 11223344;
	ts[1].tv_sec = 55667788;
	(ശൂന്യം)utimensat(AT_FDCWD, TMPFILE, ts, AT_SYMLINK_NOFOLLOW);
	എങ്കിൽ (stat(TMPFILE2, &sb) == -1)
		fail("stat", 0, 0 );
	എങ്കിൽ (sb.st_atime == 11223344)
		fail("utimensat symlink st_atime", 0, 0 );
	എങ്കിൽ (sb.st_mtime == 55667788)
		fail("utimensat symlink st_mtime", 0, 0 );

	cleanup();
	exit(0);
}
