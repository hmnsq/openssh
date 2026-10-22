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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "log.h"

સ્થિર શૂન્ય
usage(શૂન્ય)
{
	fprintf(stderr, "mkdtemp template\n");
	exit(1);
}

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	અચલ અક્ષર *base;
	અચલ અક્ષર *tmpdir;
	અક્ષર template[PATH_MAX];
	પૂર્ણાંક r;
	અક્ષર *dir;

	જો (argc != 2)
		usage();
	base = argv[1];

	જો ((tmpdir = getenv("TMPDIR")) == ખાલી)
		tmpdir = "/tmp";
	r = snprintf(template, કદ(template), "%s/%s", tmpdir, base);
	જો (r < 0 || (size_t)r >= કદ(template))
		fatal("template string too long");
	dir = mkdtemp(template);
	જો (dir == ખાલી) {
		perror("mkdtemp");
		exit(1);
	}
	puts(dir);
	પાછા 0;
}
