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

#अन्तर्भाव "includes.h"

#यदि_अपरिभाषितम् HAVE_STRTONUM
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <errno.h>

#परिभाषय INVALID		1
#परिभाषय TOOSMALL	2
#परिभाषय TOOLARGE	3

दीर्घ दीर्घ
strtonum(ध्रुव वर्ण *numstr, दीर्घ दीर्घ minval, दीर्घ दीर्घ maxval,
    ध्रुव वर्ण **errstrp)
{
	दीर्घ दीर्घ ll = 0;
	वर्ण *ep;
	पूर्णाङ्क error = 0;
	संरचना errval {
		ध्रुव वर्ण *errstr;
		पूर्णाङ्क err;
	} ev[4] = {
		{ रिक्त,		0 },
		{ "invalid",	EINVAL },
		{ "too small",	ERANGE },
		{ "too large",	ERANGE },
	};

	ev[0].err = errno;
	errno = 0;
	यदि (minval > maxval)
		error = INVALID;
	अन्यथा {
		ll = strtoll(numstr, &ep, 10);
		यदि (numstr == ep || *ep != '\0')
			error = INVALID;
		अन्यथा यदि ((ll == LLONG_MIN && errno == ERANGE) || ll < minval)
			error = TOOSMALL;
		अन्यथा यदि ((ll == LLONG_MAX && errno == ERANGE) || ll > maxval)
			error = TOOLARGE;
	}
	यदि (errstrp != रिक्त)
		*errstrp = ev[error].errstr;
	errno = ev[error].err;
	यदि (error)
		ll = 0;

	प्रत्यागम (ll);
}

#यदि_अन्तः /* HAVE_STRTONUM */
