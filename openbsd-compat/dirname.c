/*	$OpenBSD: dirname.c,v 1.13 2005/08/08 08:05:33 espie Exp $	*/

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

/* OPENBSD ORIGINAL: lib/libc/gen/dirname.c */

#ಅನ್ತರ್ಭಾವ "includes.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_DIRNAME

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <string.h>

ಅಕ್ಷರ *
dirname(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಸ್ಥಿರ ಅಕ್ಷರ dname[MAXPATHLEN];
	ಗಾತ್ರ_t len;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *endp;

	/* Empty or NULL string gets treated as "." */
	ಆದರೆ (ಮಾರ್ಗ == ಖಾಲಿ || *ಮಾರ್ಗ == '\0') {
		dname[0] = '.';
		dname[1] = '\0';
		ಹಿಂತಿರುಗಿ (dname);
	}

	/* Strip any trailing slashes */
	endp = ಮಾರ್ಗ + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ) - 1;
	ಆಗ (endp > ಮಾರ್ಗ && *endp == '/')
		endp--;

	/* Find the start of the dir */
	ಆಗ (endp > ಮಾರ್ಗ && *endp != '/')
		endp--;

	/* Either the dir is "/" or there are no slashes */
	ಆದರೆ (endp == ಮಾರ್ಗ) {
		dname[0] = *endp == '/' ? '/' : '.';
		dname[1] = '\0';
		ಹಿಂತಿರುಗಿ (dname);
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Move forward past the separating slashes */
		ಮಾಡು {
			endp--;
		} ಆಗ (endp > ಮಾರ್ಗ && *endp == '/');
	}

	len = endp - ಮಾರ್ಗ + 1;
	ಆದರೆ (len >= ಗಾತ್ರ(dname)) {
		errno = ENAMETOOLONG;
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}
	ಸ್ಮರಣೆ_ನಕಲು(dname, ಮಾರ್ಗ, len);
	dname[len] = '\0';
	ಹಿಂತಿರುಗಿ (dname);
}
#ಆದರೆ_ಅಂತ್ಯ
