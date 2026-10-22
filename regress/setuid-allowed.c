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

#شامل "includes.h"

#شامل <sys/types.h>
#اگر_تعریف_شدہ HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#اگر_ختم
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <errno.h>

ساکن خالی
usage(خالی)
{
	fprintf(stderr, "check-setuid [path]\n");
	باہر_نکلو(1);
}

صحیح
مین(صحیح argc, حرف **argv)
{
	ثابت حرف *راستہ = ".";
	ساخت statvfs sb;

	اگر (argc > 2)
		usage();
	ورنہ اگر (argc == 2)
		راستہ = argv[1];

	اگر (statvfs(راستہ, &sb) != 0) {
		/* Don't return an error if the host doesn't support statvfs */
		اگر (errno == ENOSYS)
			واپس 0;
		fprintf(stderr, "statvfs for \"%s\" failed: %s\n",
		     راستہ, strerror(errno));
	}
	واپس (sb.f_flag & ST_NOSUID) ? 1 : 0;
}


