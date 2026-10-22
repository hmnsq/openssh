/*
 * Copyright (c) 2004 Darren Tucker.
 *
 * Based originally on asprintf.c from OpenBSD:
 * Copyright (c) 1997 Todd C. Miller <Todd.Miller@courtesan.com>
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

/*
 * Don't let systems with broken printf(3) avoid our replacements
 * via asprintf(3)/vasprintf(3) calling libc internally.
 */
#अगर defined(BROKEN_SNPRINTF)
# undef HAVE_VASPRINTF
# undef HAVE_ASPRINTF
#पूर्ण_अगर

#अगर_अघोषित HAVE_VASPRINTF

#समावेश <errno.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>

#घोषणा INIT_SZ	128

पूर्णांक
vasprintf(अक्षर **str, स्थिर अक्षर *fmt, बहु_सूची ap)
{
	पूर्णांक ret = -1;
	बहु_सूची ap2;
	अक्षर *string, *newstr;
	माप_प्रकार len;

	VA_COPY(ap2, ap);
	अगर ((string = दो_स्मृति(INIT_SZ)) == शून्य)
		जाओ fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	अगर (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} अन्यथा अगर (ret == पूर्णांक_उच्च || ret < 0) { /* Bad length */
		मुक्त(string);
		जाओ fail;
	} अन्यथा {	/* bigger than initial, realloc allowing for nul */
		len = (माप_प्रकार)ret + 1;
		अगर ((newstr = पुनः_स्मृति(string, len)) == शून्य) {
			मुक्त(string);
			जाओ fail;
		} अन्यथा {
			बहु_पूर्ण(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			अगर (ret >= 0 && (माप_प्रकार)ret < len) {
				*str = newstr;
			} अन्यथा { /* failed with realloc'ed string, give up */
				मुक्त(newstr);
				जाओ fail;
			}
		}
	}
	बहु_पूर्ण(ap2);
	वापस (ret);

fail:
	*str = शून्य;
	त्रुटि_सं = ENOMEM;
	बहु_पूर्ण(ap2);
	वापस (-1);
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_ASPRINTF
पूर्णांक asprintf(अक्षर **str, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची ap;
	पूर्णांक ret;

	*str = शून्य;
	बहु_शुरू(ap, fmt);
	ret = vasprintf(str, fmt, ap);
	बहु_पूर्ण(ap);

	वापस ret;
}
#पूर्ण_अगर
