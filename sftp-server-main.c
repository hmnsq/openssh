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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <pwd.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <unistd.h>

#समावेश "log.h"
#समावेश "sftp.h"
#समावेश "misc.h"
#समावेश "xmalloc.h"

व्योम
cleanup_exit(पूर्णांक i)
{
	sftp_server_cleanup_exit(i);
}

पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	काष्ठा passwd *user_pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	अगर ((user_pw = getpwuid(getuid())) == शून्य) {
		ख_लिखो(मानक_त्रुटि, "No user found for uid %lu\n",
		    (u_long)getuid());
		वापस 1;
	}

	वापस (sftp_server_main(argc, argv, user_pw));
}
