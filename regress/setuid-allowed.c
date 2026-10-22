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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#నిర్వచితమైతే HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#అయితే_ముగింపు
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <errno.h>

స్థిర శూన్య
usage(శూన్య)
{
	fprintf(stderr, "check-setuid [path]\n");
	నిష్క్రమించు(1);
}

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	స్థిరరాశి అక్షరం *మార్గం = ".";
	నిర్మాణం statvfs sb;

	ఒకవేళ (argc > 2)
		usage();
	లేకపోతే ఒకవేళ (argc == 2)
		మార్గం = argv[1];

	ఒకవేళ (statvfs(మార్గం, &sb) != 0) {
		/* Don't return an error if the host doesn't support statvfs */
		ఒకవేళ (errno == ENOSYS)
			తిరిగి 0;
		fprintf(stderr, "statvfs for \"%s\" failed: %s\n",
		     మార్గం, strerror(errno));
	}
	తిరిగి (sb.f_flag & ST_NOSUID) ? 1 : 0;
}


