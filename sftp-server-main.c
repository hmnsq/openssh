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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sftp.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "xmalloc.h"

શૂન્ય
cleanup_exit(પૂર્ણાંક i)
{
	sftp_server_cleanup_exit(i);
}

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	સંરચના passwd *user_pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	જો ((user_pw = getpwuid(getuid())) == ખાલી) {
		fprintf(stderr, "No user found for uid %lu\n",
		    (u_long)getuid());
		પાછા 1;
	}

	પાછા (sftp_server_main(argc, argv, user_pw));
}
