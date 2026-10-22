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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#ifdef HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#endif
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <errno.h>

സ്ഥിതം ശൂന്യം
usage(ശൂന്യം)
{
	fprintf(stderr, "check-setuid [path]\n");
	exit(1);
}

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	സ്ഥിരം അക്ഷരം *path = ".";
	ഘടന statvfs sb;

	എങ്കിൽ (argc > 2)
		usage();
	അല്ലെങ്കിൽ എങ്കിൽ (argc == 2)
		path = argv[1];

	എങ്കിൽ (statvfs(path, &sb) != 0) {
		/* Don't return an error if the host doesn't support statvfs */
		എങ്കിൽ (errno == ENOSYS)
			തിരികെ 0;
		fprintf(stderr, "statvfs for \"%s\" failed: %s\n",
		     path, strerror(errno));
	}
	തിരികെ (sb.f_flag & ST_NOSUID) ? 1 : 0;
}


