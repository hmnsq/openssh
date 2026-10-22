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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <limits.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "log.h"

స్థిర శూన్య
usage(శూన్య)
{
	fprintf(stderr, "mkdtemp template\n");
	నిష్క్రమించు(1);
}

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	స్థిరరాశి అక్షరం *పునాది;
	స్థిరరాశి అక్షరం *tmpdir;
	అక్షరం మూస[PATH_MAX];
	పూర్ణాంకం r;
	అక్షరం *dir;

	ఒకవేళ (argc != 2)
		usage();
	పునాది = argv[1];

	ఒకవేళ ((tmpdir = getenv("TMPDIR")) == ఖాళీ)
		tmpdir = "/tmp";
	r = snprintf(మూస, పరిమాణం(మూస), "%s/%s", tmpdir, పునాది);
	ఒకవేళ (r < 0 || (కొలత_t)r >= పరిమాణం(మూస))
		fatal("template string too long");
	dir = mkdtemp(మూస);
	ఒకవేళ (dir == ఖాళీ) {
		perror("mkdtemp");
		నిష్క్రమించు(1);
	}
	puts(dir);
	తిరిగి 0;
}
