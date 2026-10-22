/*	$OpenBSD: strndup.c,v 1.2 2015/08/31 02:53:57 guenther Exp $	*/

/*
 * Copyright (c) 2010 Todd C. Miller <Todd.Miller@courtesan.com>
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

#अन्तर्भाव "includes.h"
#जर !defined(HAVE_STRNDUP) || defined(BROKEN_STRNDUP)
#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

अक्षर *
strndup(स्थिरांक अक्षर *str, माप_प्रकार maxlen)
{
	अक्षर *copy;
	माप_प्रकार len;

	len = strnlen(str, maxlen);
	copy = दो_स्मृति(len + 1);
	जर (copy != रिक्त) {
		(शून्य)स_नकल(copy, str, len);
		copy[len] = '\0';
	}

	परत copy;
}
DEF_WEAK(strndup);
#endif  /* HAVE_STRNDUP */
