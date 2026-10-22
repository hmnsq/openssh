/* $OpenBSD: sftp-server-main.c,v 1.6 2019/06/06 05:13:13 otto Exp $ */
/*
 * Copyright (c) 2008 Markus Friedl.  All rights reserved.
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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sftp.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "xmalloc.h"

ശൂന്യം
cleanup_exit(പൂർണ്ണസംഖ്യ i)
{
	sftp_server_cleanup_exit(i);
}

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	ഘടന passwd *user_pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	എങ്കിൽ ((user_pw = getpwuid(getuid())) == ശൂന്യ) {
		fprintf(stderr, "No user found for uid %lu\n",
		    (u_long)getuid());
		തിരികെ 1;
	}

	തിരികെ (sftp_server_main(argc, argv, user_pw));
}
