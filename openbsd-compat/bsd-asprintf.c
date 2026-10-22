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

#अन्तर्भाव "includes.h"

/*
 * Don't let systems with broken printf(3) avoid our replacements
 * via asprintf(3)/vasprintf(3) calling libc internally.
 */
#जर defined(BROKEN_SNPRINTF)
# undef HAVE_VASPRINTF
# undef HAVE_ASPRINTF
#endif

#ifndef HAVE_VASPRINTF

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>

#define INIT_SZ	128

पूर्णांक
vasprintf(अक्षर **str, स्थिरांक अक्षर *fmt, बहु_सूची ap)
{
	पूर्णांक ret = -1;
	बहु_सूची ap2;
	अक्षर *string, *newstr;
	माप_प्रकार len;

	VA_COPY(ap2, ap);
	जर ((string = दो_स्मृति(INIT_SZ)) == रिक्त)
		जा fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	जर (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} अन्यथा जर (ret == पूर्णांक_उच्च || ret < 0) { /* Bad length */
		मुक्त(string);
		जा fail;
	} अन्यथा {	/* bigger than initial, realloc allowing for nul */
		len = (माप_प्रकार)ret + 1;
		जर ((newstr = पुनः_स्मृति(string, len)) == रिक्त) {
			मुक्त(string);
			जा fail;
		} अन्यथा {
			बहु_पूर्ण(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			जर (ret >= 0 && (माप_प्रकार)ret < len) {
				*str = newstr;
			} अन्यथा { /* failed with realloc'ed string, give up */
				मुक्त(newstr);
				जा fail;
			}
		}
	}
	बहु_पूर्ण(ap2);
	परत (ret);

fail:
	*str = रिक्त;
	त्रुटि_सं = ENOMEM;
	बहु_पूर्ण(ap2);
	परत (-1);
}
#endif

#ifndef HAVE_ASPRINTF
पूर्णांक asprintf(अक्षर **str, स्थिरांक अक्षर *fmt, ...)
{
	बहु_सूची ap;
	पूर्णांक ret;

	*str = रिक्त;
	बहु_शुरू(ap, fmt);
	ret = vasprintf(str, fmt, ap);
	बहु_पूर्ण(ap);

	परत ret;
}
#endif
