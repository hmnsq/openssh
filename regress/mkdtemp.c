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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "log.h"

நிலையான வெறுமை
usage(வெறுமை)
{
	fprintf(stderr, "mkdtemp template\n");
	exit(1);
}

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	மாறிலி எழுத்து *base;
	மாறிலி எழுத்து *tmpdir;
	எழுத்து template[PATH_MAX];
	முழு r;
	எழுத்து *dir;

	எனில் (argc != 2)
		usage();
	base = argv[1];

	எனில் ((tmpdir = getenv("TMPDIR")) == வெற்று)
		tmpdir = "/tmp";
	r = snprintf(template, அளவு(template), "%s/%s", tmpdir, base);
	எனில் (r < 0 || (size_t)r >= அளவு(template))
		fatal("template string too long");
	dir = mkdtemp(template);
	எனில் (dir == வெற்று) {
		perror("mkdtemp");
		exit(1);
	}
	puts(dir);
	திரும்பு 0;
}
