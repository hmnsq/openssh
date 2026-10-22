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

#અન્તર્ભાવ "includes.h"

#ifndef HAVE_STRTONUM
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <errno.h>

#define INVALID		1
#define TOOSMALL	2
#define TOOLARGE	3

long long
strtonum(અચલ અક્ષર *numstr, long long minval, long long maxval,
    અચલ અક્ષર **errstrp)
{
	long long ll = 0;
	અક્ષર *ep;
	પૂર્ણાંક error = 0;
	સંરચના errval {
		અચલ અક્ષર *errstr;
		પૂર્ણાંક err;
	} ev[4] = {
		{ ખાલી,		0 },
		{ "invalid",	EINVAL },
		{ "too small",	ERANGE },
		{ "too large",	ERANGE },
	};

	ev[0].err = errno;
	errno = 0;
	જો (minval > maxval)
		error = INVALID;
	નહીંતર {
		ll = strtoll(numstr, &ep, 10);
		જો (numstr == ep || *ep != '\0')
			error = INVALID;
		નહીંતર જો ((ll == LLONG_MIN && errno == ERANGE) || ll < minval)
			error = TOOSMALL;
		નહીંતર જો ((ll == LLONG_MAX && errno == ERANGE) || ll > maxval)
			error = TOOLARGE;
	}
	જો (errstrp != ખાલી)
		*errstrp = ev[error].errstr;
	errno = ev[error].err;
	જો (error)
		ll = 0;

	પાછા (ll);
}

#endif /* HAVE_STRTONUM */
