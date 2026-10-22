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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "log.h"

സ്ഥിതം ശൂന്യം
usage(ശൂന്യം)
{
	fprintf(stderr, "mkdtemp template\n");
	exit(1);
}

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	സ്ഥിരം അക്ഷരം *base;
	സ്ഥിരം അക്ഷരം *tmpdir;
	അക്ഷരം template[PATH_MAX];
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം *dir;

	എങ്കിൽ (argc != 2)
		usage();
	base = argv[1];

	എങ്കിൽ ((tmpdir = getenv("TMPDIR")) == ശൂന്യ)
		tmpdir = "/tmp";
	r = snprintf(template, വലുപ്പം(template), "%s/%s", tmpdir, base);
	എങ്കിൽ (r < 0 || (size_t)r >= വലുപ്പം(template))
		fatal("template string too long");
	dir = mkdtemp(template);
	എങ്കിൽ (dir == ശൂന്യ) {
		perror("mkdtemp");
		exit(1);
	}
	puts(dir);
	തിരികെ 0;
}
