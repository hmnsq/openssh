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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifndef HAVE_STRTONUM
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>

#define INVALID		1
#define TOOSMALL	2
#define TOOLARGE	3

long long
strtonum(ଅଚଳ ଅକ୍ଷର *numstr, long long minval, long long maxval,
    ଅଚଳ ଅକ୍ଷର **errstrp)
{
	long long ll = 0;
	ଅକ୍ଷର *ep;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା error = 0;
	ସଂରଚନା errval {
		ଅଚଳ ଅକ୍ଷର *errstr;
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା err;
	} ev[4] = {
		{ ଖାଲି,		0 },
		{ "invalid",	EINVAL },
		{ "too small",	ERANGE },
		{ "too large",	ERANGE },
	};

	ev[0].err = errno;
	errno = 0;
	ଯଦି (minval > maxval)
		error = INVALID;
	ଅନ୍ୟଥା {
		ll = strtoll(numstr, &ep, 10);
		ଯଦି (numstr == ep || *ep != '\0')
			error = INVALID;
		ଅନ୍ୟଥା ଯଦି ((ll == LLONG_MIN && errno == ERANGE) || ll < minval)
			error = TOOSMALL;
		ଅନ୍ୟଥା ଯଦି ((ll == LLONG_MAX && errno == ERANGE) || ll > maxval)
			error = TOOLARGE;
	}
	ଯଦି (errstrp != ଖାଲି)
		*errstrp = ev[error].errstr;
	errno = ev[error].err;
	ଯଦି (error)
		ll = 0;

	ଫେରନ୍ତୁ (ll);
}

#endif /* HAVE_STRTONUM */
