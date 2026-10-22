/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
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

/* $OpenBSD$ */

#include "includes.h"

#include <sys/types.h>
#ifdef HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

static void
usage(void)
{
	fprintf(stderr, "check-setuid [path]\n");
	exit(1);
}

ចំនួនគត់
main(ចំនួនគត់ argc, var_na **argv)
{
	const var_na *path = ".";
	sa_nracanaa statvfs sb;

	ប្រសិនបើ (argc > 2)
		usage();
	បើមិនដូច្នេះ ប្រសិនបើ (argc == 2)
		path = argv[1];

	ប្រសិនបើ (statvfs(path, &sb) != 0) {
		/* Don't return an error if the host doesn't support statvfs */
		ប្រសិនបើ (errno == ENOSYS)
			ត្រឡប់ 0;
		fprintf(stderr, "statvfs for \"%s\" failed: %s\n",
		     path, strerror(errno));
	}
	ត្រឡប់ (sb.f_flag & ST_NOSUID) ? 1 : 0;
}


