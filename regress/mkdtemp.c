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

#ضمن "includes.h"

#ضمن <limits.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <unistd.h>

#ضمن "log.h"

ساكن فراغ
usage(فراغ)
{
	fprintf(stderr, "mkdtemp template\n");
	exit(1);
}

صحيح
main(صحيح argc, حرف **argv)
{
	ثابت حرف *base;
	ثابت حرف *tmpdir;
	حرف template[PATH_MAX];
	صحيح r;
	حرف *dir;

	إذا (argc != 2)
		usage();
	base = argv[1];

	إذا ((tmpdir = getenv("TMPDIR")) == عدم)
		tmpdir = "/tmp";
	r = snprintf(template, حجم(template), "%s/%s", tmpdir, base);
	إذا (r < 0 || (size_t)r >= حجم(template))
		fatal("template string too long");
	dir = mkdtemp(template);
	إذا (dir == عدم) {
		perror("mkdtemp");
		exit(1);
	}
	puts(dir);
	أرجع 0;
}
