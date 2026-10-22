/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
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

/* $OpenBSD$ */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#ifdef HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#endif
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <errno.h>

স্থির শূন্য
usage(শূন্য)
{
	fprintf(stderr, "check-setuid [path]\n");
	exit(1);
}

পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, বর্ণ **argv)
{
	ধ্রুব বর্ণ *path = ".";
	সংরচনা statvfs sb;

	যদি (argc > 2)
		usage();
	অন্যথা যদি (argc == 2)
		path = argv[1];

	যদি (statvfs(path, &sb) != 0) {
		/* Don't return an error if the host doesn't support statvfs */
		যদি (errno == ENOSYS)
			প্রত্যাগম 0;
		fprintf(stderr, "statvfs for \"%s\" failed: %s\n",
		     path, strerror(errno));
	}
	প্রত্যাগম (sb.f_flag & ST_NOSUID) ? 1 : 0;
}


