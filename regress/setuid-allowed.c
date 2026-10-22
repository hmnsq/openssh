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

#समावेश "includes.h"

#समावेश <sys/types.h>
#अगर_घोषित HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#पूर्ण_अगर
#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <errno.h>

अटल व्योम
usage(व्योम)
{
	ख_लिखो(मानक_त्रुटि, "check-setuid [path]\n");
	निकास(1);
}

पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	स्थिर अक्षर *path = ".";
	काष्ठा statvfs sb;

	अगर (argc > 2)
		usage();
	अन्यथा अगर (argc == 2)
		path = argv[1];

	अगर (statvfs(path, &sb) != 0) {
		/* Don't return an error if the host doesn't support statvfs */
		अगर (त्रुटि_सं == ENOSYS)
			वापस 0;
		ख_लिखो(मानक_त्रुटि, "statvfs for \"%s\" failed: %s\n",
		     path, म_त्रुटि(त्रुटि_सं));
	}
	वापस (sb.f_flag & ST_NOSUID) ? 1 : 0;
}


