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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sftp.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "xmalloc.h"

வெறுமை
cleanup_exit(முழு i)
{
	sftp_server_cleanup_exit(i);
}

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	கட்டமைப்பு passwd *user_pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	எனில் ((user_pw = getpwuid(getuid())) == வெற்று) {
		fprintf(stderr, "No user found for uid %lu\n",
		    (u_long)getuid());
		திரும்பு 1;
	}

	திரும்பு (sftp_server_main(argc, argv, user_pw));
}
