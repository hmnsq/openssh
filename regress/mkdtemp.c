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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

ਸਥਿਰ ਖਾਲੀ
usage(ਖਾਲੀ)
{
	fprintf(stderr, "mkdtemp template\n");
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਅਚਲ ਅੱਖਰ *ਅਧਾਰ;
	ਅਚਲ ਅੱਖਰ *tmpdir;
	ਅੱਖਰ ਸਾਂਚਾ[PATH_MAX];
	ਪੂਰਨ r;
	ਅੱਖਰ *dir;

	ਜੇ (argc != 2)
		usage();
	ਅਧਾਰ = argv[1];

	ਜੇ ((tmpdir = getenv("TMPDIR")) == ਨਿਰਾ)
		tmpdir = "/tmp";
	r = snprintf(ਸਾਂਚਾ, ਆਕਾਰ(ਸਾਂਚਾ), "%s/%s", tmpdir, ਅਧਾਰ);
	ਜੇ (r < 0 || (ਮਾਪ_t)r >= ਆਕਾਰ(ਸਾਂਚਾ))
		fatal("template string too long");
	dir = mkdtemp(ਸਾਂਚਾ);
	ਜੇ (dir == ਨਿਰਾ) {
		perror("mkdtemp");
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	puts(dir);
	ਵਾਪਸ 0;
}
