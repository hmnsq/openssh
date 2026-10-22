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

#شامل "includes.h"

#شامل <limits.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <unistd.h>

#شامل "log.h"

ایستا تهی
usage(تهی)
{
	fprintf(stderr, "mkdtemp template\n");
	exit(1);
}

صحیح
اصلی(صحیح argc, نویسه **argv)
{
	ثابت نویسه *base;
	ثابت نویسه *tmpdir;
	نویسه template[PATH_MAX];
	صحیح r;
	نویسه *dir;

	اگر (argc != 2)
		usage();
	base = argv[1];

	اگر ((tmpdir = getenv("TMPDIR")) == پوچ)
		tmpdir = "/tmp";
	r = snprintf(template, اندازه(template), "%s/%s", tmpdir, base);
	اگر (r < 0 || (size_t)r >= اندازه(template))
		fatal("template string too long");
	dir = mkdtemp(template);
	اگر (dir == پوچ) {
		perror("mkdtemp");
		exit(1);
	}
	puts(dir);
	بازگشت 0;
}
