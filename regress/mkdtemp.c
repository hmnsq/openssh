/*
 * Copyright (c) 2017 Colin Watson <cjwatson@debian.org>
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

/* Roughly equivalent to "mktemp -d -t TEMPLATE", but portable. */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "log.h"

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	fprintf(stderr, "mkdtemp template\n");
	ನಿರ್ಗಮಿಸು(1);
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ತಳ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *tmpdir;
	ಅಕ್ಷರ ಮಾದರಿ[PATH_MAX];
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ *dir;

	ಆದರೆ (argc != 2)
		usage();
	ತಳ = argv[1];

	ಆದರೆ ((tmpdir = getenv("TMPDIR")) == ಖಾಲಿ)
		tmpdir = "/tmp";
	r = snprintf(ಮಾದರಿ, ಗಾತ್ರ(ಮಾದರಿ), "%s/%s", tmpdir, ತಳ);
	ಆದರೆ (r < 0 || (ಗಾತ್ರ_t)r >= ಗಾತ್ರ(ಮಾದರಿ))
		fatal("template string too long");
	dir = mkdtemp(ಮಾದರಿ);
	ಆದರೆ (dir == ಖಾಲಿ) {
		perror("mkdtemp");
		ನಿರ್ಗಮಿಸು(1);
	}
	puts(dir);
	ಹಿಂತಿರುಗಿ 0;
}
