/*	$OpenBSD: basename.c,v 1.14 2005/08/08 08:05:33 espie Exp $	*/

/*
 * Copyright (c) 1997, 2004 Todd C. Miller <Todd.Miller@courtesan.com>
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

/* OPENBSD ORIGINAL: lib/libc/gen/basename.c */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_BASENAME
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

ਅੱਖਰ *
basename(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਸਥਿਰ ਅੱਖਰ bname[MAXPATHLEN];
	ਮਾਪ_t len;
	ਅਚਲ ਅੱਖਰ *endp, *startp;

	/* Empty or NULL string gets treated as "." */
	ਜੇ (ਰਸਤਾ == ਨਿਰਾ || *ਰਸਤਾ == '\0') {
		bname[0] = '.';
		bname[1] = '\0';
		ਵਾਪਸ (bname);
	}

	/* Strip any trailing slashes */
	endp = ਰਸਤਾ + ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ) - 1;
	ਜਦੋਂ (endp > ਰਸਤਾ && *endp == '/')
		endp--;

	/* All slashes becomes "/" */
	ਜੇ (endp == ਰਸਤਾ && *endp == '/') {
		bname[0] = '/';
		bname[1] = '\0';
		ਵਾਪਸ (bname);
	}

	/* Find the start of the base */
	startp = endp;
	ਜਦੋਂ (startp > ਰਸਤਾ && *(startp - 1) != '/')
		startp--;

	len = endp - startp + 1;
	ਜੇ (len >= ਆਕਾਰ(bname)) {
		errno = ENAMETOOLONG;
		ਵਾਪਸ (ਨਿਰਾ);
	}
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(bname, startp, len);
	bname[len] = '\0';
	ਵਾਪਸ (bname);
}

#ਜੇ_ਅੰਤ /* !defined(HAVE_BASENAME) */
