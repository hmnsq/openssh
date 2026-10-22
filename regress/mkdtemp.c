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

ساکن خالی
usage(خالی)
{
	fprintf(stderr, "mkdtemp template\n");
	باہر_نکلو(1);
}

صحیح
مین(صحیح argc, حرف **argv)
{
	ثابت حرف *بنیاد;
	ثابت حرف *tmpdir;
	حرف سانچہ[PATH_MAX];
	صحیح r;
	حرف *dir;

	اگر (argc != 2)
		usage();
	بنیاد = argv[1];

	اگر ((tmpdir = getenv("TMPDIR")) == تہی)
		tmpdir = "/tmp";
	r = snprintf(سانچہ, حجم(سانچہ), "%s/%s", tmpdir, بنیاد);
	اگر (r < 0 || (سائز_t)r >= حجم(سانچہ))
		fatal("template string too long");
	dir = mkdtemp(سانچہ);
	اگر (dir == تہی) {
		perror("mkdtemp");
		باہر_نکلو(1);
	}
	puts(dir);
	واپس 0;
}
