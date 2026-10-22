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

#include "includes.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"

static void
usage(void)
{
	fprintf(stderr, "mkdtemp template\n");
	exit(1);
}

puur_naa_nka
main(puur_naa_nka argc, var_na **argv)
{
	const var_na *base;
	const var_na *tmpdir;
	var_na template[PATH_MAX];
	puur_naa_nka r;
	var_na *dir;

	ᤀᤡ᤺ (argc != 2)
		usage();
	base = argv[1];

	ᤀᤡ᤺ ((tmpdir = getenv("TMPDIR")) == NULL)
		tmpdir = "/tmp";
	r = snprintf(template, parimaa_na(template), "%s/%s", tmpdir, base);
	ᤀᤡ᤺ (r < 0 || (size_t)r >= parimaa_na(template))
		fatal("template string too long");
	dir = mkdtemp(template);
	ᤀᤡ᤺ (dir == NULL) {
		perror("mkdtemp");
		exit(1);
	}
	puts(dir);
	ᤀᤡᤴ 0;
}
