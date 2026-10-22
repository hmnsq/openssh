/*	$OpenBSD: strtonum.c,v 1.6 2004/08/03 19:38:01 millert Exp $	*/

/*
 * Copyright (c) 2004 Ted Unangst and Todd Miller
 * All rights reserved.
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

/* OPENBSD ORIGINAL: lib/libc/stdlib/strtonum.c */

#समावेश "includes.h"

#अगर_अघोषित HAVE_STRTONUM
#समावेश <stdlib.h>
#समावेश <limits.h>
#समावेश <errno.h>

#घोषणा INVALID		1
#घोषणा TOOSMALL	2
#घोषणा TOOLARGE	3

दीर्घ दीर्घ
strtonum(स्थिर अक्षर *numstr, दीर्घ दीर्घ minval, दीर्घ दीर्घ maxval,
    स्थिर अक्षर **errstrp)
{
	दीर्घ दीर्घ ll = 0;
	अक्षर *ep;
	पूर्णांक error = 0;
	काष्ठा errval {
		स्थिर अक्षर *errstr;
		पूर्णांक err;
	} ev[4] = {
		{ शून्य,		0 },
		{ "invalid",	EINVAL },
		{ "too small",	दुस्फल },
		{ "too large",	दुस्फल },
	};

	ev[0].err = त्रुटि_सं;
	त्रुटि_सं = 0;
	अगर (minval > maxval)
		error = INVALID;
	अन्यथा {
		ll = strtoll(numstr, &ep, 10);
		अगर (numstr == ep || *ep != '\0')
			error = INVALID;
		अन्यथा अगर ((ll == LLONG_MIN && त्रुटि_सं == दुस्फल) || ll < minval)
			error = TOOSMALL;
		अन्यथा अगर ((ll == LLONG_MAX && त्रुटि_सं == दुस्फल) || ll > maxval)
			error = TOOLARGE;
	}
	अगर (errstrp != शून्य)
		*errstrp = ev[error].errstr;
	त्रुटि_सं = ev[error].err;
	अगर (error)
		ll = 0;

	वापस (ll);
}

#पूर्ण_अगर /* HAVE_STRTONUM */
