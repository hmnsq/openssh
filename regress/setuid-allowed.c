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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#यदि_परिभाषितम् HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#यदि_अन्तः
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <errno.h>

स्थिर शून्य
usage(शून्य)
{
	fprintf(stderr, "check-setuid [path]\n");
	निर्गच्छ(1);
}

पूर्णाङ्क
मुख्यम्(पूर्णाङ्क argc, वर्ण **argv)
{
	ध्रुव वर्ण *मार्गः = ".";
	संरचना statvfs sb;

	यदि (argc > 2)
		usage();
	अन्यथा यदि (argc == 2)
		मार्गः = argv[1];

	यदि (statvfs(मार्गः, &sb) != 0) {
		/* Don't return an error if the host doesn't support statvfs */
		यदि (errno == ENOSYS)
			प्रत्यागम 0;
		fprintf(stderr, "statvfs for \"%s\" failed: %s\n",
		     मार्गः, strerror(errno));
	}
	प्रत्यागम (sb.f_flag & ST_NOSUID) ? 1 : 0;
}


