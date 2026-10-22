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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "log.h"

স্থির শূন্য
usage(শূন্য)
{
	fprintf(stderr, "mkdtemp template\n");
	exit(1);
}

পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	ধ্রুবক অক্ষর *base;
	ধ্রুবক অক্ষর *tmpdir;
	অক্ষর template[PATH_MAX];
	পূর্ণসংখ্যা r;
	অক্ষর *dir;

	যদি (argc != 2)
		usage();
	base = argv[1];

	যদি ((tmpdir = getenv("TMPDIR")) == ফাঁকা)
		tmpdir = "/tmp";
	r = snprintf(template, আকার(template), "%s/%s", tmpdir, base);
	যদি (r < 0 || (আকার_t)r >= আকার(template))
		fatal("template string too long");
	dir = mkdtemp(template);
	যদি (dir == ফাঁকা) {
		perror("mkdtemp");
		exit(1);
	}
	puts(dir);
	ফেরত 0;
}
