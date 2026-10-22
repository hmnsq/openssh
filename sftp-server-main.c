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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <pwd.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <unistd.h>

#شامل "log.h"
#شامل "sftp.h"
#شامل "misc.h"
#شامل "xmalloc.h"

تهی
cleanup_exit(صحیح i)
{
	sftp_server_cleanup_exit(i);
}

صحیح
اصلی(صحیح argc, نویسه **argv)
{
	ساختار passwd *user_pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	اگر ((user_pw = getpwuid(getuid())) == پوچ) {
		fprintf(stderr, "No user found for uid %lu\n",
		    (u_long)getuid());
		بازگشت 1;
	}

	بازگشت (sftp_server_main(argc, argv, user_pw));
}
