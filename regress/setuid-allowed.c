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

#ضمن "includes.h"

#ضمن <sys/types.h>
#اگر_تعریف_شده HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#پایان_اگر
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <errno.h>

ساكن فراغ
usage(فراغ)
{
	fprintf(stderr, "check-setuid [path]\n");
	خروج(1);
}

صحيح
اصلی(صحيح argc, حرف **argv)
{
	ثابت حرف *مسیر = ".";
	بنية statvfs sb;

	إذا (argc > 2)
		usage();
	وإلا إذا (argc == 2)
		مسیر = argv[1];

	إذا (statvfs(مسیر, &sb) != 0) {
		/* Don't return an error if the host doesn't support statvfs */
		إذا (errno == ENOSYS)
			أرجع 0;
		fprintf(stderr, "statvfs for \"%s\" failed: %s\n",
		     مسیر, strerror(errno));
	}
	أرجع (sb.f_flag & ST_NOSUID) ? 1 : 0;
}


