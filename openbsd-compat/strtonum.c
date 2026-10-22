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

#ضمن "includes.h"

#جے_بنا_تعریف HAVE_STRTONUM
#ضمن <stdlib.h>
#ضمن <limits.h>
#ضمن <errno.h>

#تعریف_کرو INVALID		1
#تعریف_کرو TOOSMALL	2
#تعریف_کرو TOOLARGE	3

لما لما
strtonum(ثابت حرف *numstr, لما لما minval, لما لما maxval,
    ثابت حرف **errstrp)
{
	لما لما ll = 0;
	حرف *ep;
	صحيح error = 0;
	بنية errval {
		ثابت حرف *errstr;
		صحيح err;
	} ev[4] = {
		{ عدم,		0 },
		{ "invalid",	EINVAL },
		{ "too small",	ERANGE },
		{ "too large",	ERANGE },
	};

	ev[0].err = errno;
	errno = 0;
	إذا (minval > maxval)
		error = INVALID;
	وإلا {
		ll = strtoll(numstr, &ep, 10);
		إذا (numstr == ep || *ep != '\0')
			error = INVALID;
		وإلا إذا ((ll == LLONG_MIN && errno == ERANGE) || ll < minval)
			error = TOOSMALL;
		وإلا إذا ((ll == LLONG_MAX && errno == ERANGE) || ll > maxval)
			error = TOOLARGE;
	}
	إذا (errstrp != عدم)
		*errstrp = ev[error].errstr;
	errno = ev[error].err;
	إذا (error)
		ll = 0;

	أرجع (ll);
}

#جے_انت /* HAVE_STRTONUM */
