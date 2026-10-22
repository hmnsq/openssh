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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>

ਸਥਿਰ ਖਾਲੀ
usage(ਖਾਲੀ)
{
	fprintf(stderr, "check-setuid [path]\n");
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਅਚਲ ਅੱਖਰ *ਰਸਤਾ = ".";
	ਬਣਤਰ statvfs sb;

	ਜੇ (argc > 2)
		usage();
	ਨਹੀਂਤਾਂ ਜੇ (argc == 2)
		ਰਸਤਾ = argv[1];

	ਜੇ (statvfs(ਰਸਤਾ, &sb) != 0) {
		/* Don't return an error if the host doesn't support statvfs */
		ਜੇ (errno == ENOSYS)
			ਵਾਪਸ 0;
		fprintf(stderr, "statvfs for \"%s\" failed: %s\n",
		     ਰਸਤਾ, strerror(errno));
	}
	ਵਾਪਸ (sb.f_flag & ST_NOSUID) ? 1 : 0;
}


