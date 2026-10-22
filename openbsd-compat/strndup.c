/*	$OpenBSD: strndup.c,v 1.2 2015/08/31 02:53:57 guenther Exp $	*/

/*
 * Copyright (c) 2010 Todd C. Miller <Todd.Miller@courtesan.com>
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

#అన్తర్భావ "includes.h"
#ఒకవేళ !defined(HAVE_STRNDUP) || defined(BROKEN_STRNDUP)
#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

అక్షరం *
strndup(స్థిరరాశి అక్షరం *str, కొలత_t maxlen)
{
	అక్షరం *copy;
	కొలత_t len;

	len = strnlen(str, maxlen);
	copy = జ్ఞాపకం_ఇవ్వు(len + 1);
	ఒకవేళ (copy != ఖాళీ) {
		(శూన్య)జ్ఞాపకం_నకలు(copy, str, len);
		copy[len] = '\0';
	}

	తిరిగి copy;
}
DEF_WEAK(strndup);
#అయితే_ముగింపు  /* HAVE_STRNDUP */
