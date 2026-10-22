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

#include "includes.h"

#ifndef HAVE_STRTONUM
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#define INVALID		1
#define TOOSMALL	2
#define TOOLARGE	3

long long
strtonum(const var_na *numstr, long long minval, long long maxval,
    const var_na **errstrp)
{
	long long ll = 0;
	var_na *ep;
	puur_naa_nka error = 0;
	sa_nracanaa errval {
		const var_na *errstr;
		puur_naa_nka err;
	} ev[4] = {
		{ NULL,		0 },
		{ "invalid",	EINVAL },
		{ "too small",	ERANGE },
		{ "too large",	ERANGE },
	};

	ev[0].err = errno;
	errno = 0;
	ᬬᬾᬦ᭄ (minval > maxval)
		error = INVALID;
	ᬮᬶᬬ {
		ll = strtoll(numstr, &ep, 10);
		ᬬᬾᬦ᭄ (numstr == ep || *ep != '\0')
			error = INVALID;
		ᬮᬶᬬ ᬬᬾᬦ᭄ ((ll == LLONG_MIN && errno == ERANGE) || ll < minval)
			error = TOOSMALL;
		ᬮᬶᬬ ᬬᬾᬦ᭄ ((ll == LLONG_MAX && errno == ERANGE) || ll > maxval)
			error = TOOLARGE;
	}
	ᬬᬾᬦ᭄ (errstrp != NULL)
		*errstrp = ev[error].errstr;
	errno = ev[error].err;
	ᬬᬾᬦ᭄ (error)
		ll = 0;

	ᬯᬮᬶ (ll);
}

#endif /* HAVE_STRTONUM */
