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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <errno.h>

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	fprintf(stderr, "check-setuid [path]\n");
	ನಿರ್ಗಮಿಸು(1);
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ = ".";
	ರಚನೆ statvfs sb;

	ಆದರೆ (argc > 2)
		usage();
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (argc == 2)
		ಮಾರ್ಗ = argv[1];

	ಆದರೆ (statvfs(ಮಾರ್ಗ, &sb) != 0) {
		/* Don't return an error if the host doesn't support statvfs */
		ಆದರೆ (errno == ENOSYS)
			ಹಿಂತಿರುಗಿ 0;
		fprintf(stderr, "statvfs for \"%s\" failed: %s\n",
		     ಮಾರ್ಗ, strerror(errno));
	}
	ಹಿಂತಿರುಗಿ (sb.f_flag & ST_NOSUID) ? 1 : 0;
}


