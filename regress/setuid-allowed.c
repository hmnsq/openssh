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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#ifdef HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#endif
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <errno.h>

நிலையான வெறுமை
usage(வெறுமை)
{
	fprintf(stderr, "check-setuid [path]\n");
	exit(1);
}

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	மாறிலி எழுத்து *path = ".";
	கட்டமைப்பு statvfs sb;

	எனில் (argc > 2)
		usage();
	இல்லையெனில் எனில் (argc == 2)
		path = argv[1];

	எனில் (statvfs(path, &sb) != 0) {
		/* Don't return an error if the host doesn't support statvfs */
		எனில் (errno == ENOSYS)
			திரும்பு 0;
		fprintf(stderr, "statvfs for \"%s\" failed: %s\n",
		     path, strerror(errno));
	}
	திரும்பு (sb.f_flag & ST_NOSUID) ? 1 : 0;
}


