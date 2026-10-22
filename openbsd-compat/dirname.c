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

#అన్తర్భావ "includes.h"
#నిర్వచితం_కాకపోతే HAVE_DIRNAME

#అన్తర్భావ <errno.h>
#అన్తర్భావ <string.h>

అక్షరం *
dirname(స్థిరరాశి అక్షరం *మార్గం)
{
	స్థిర అక్షరం dname[MAXPATHLEN];
	కొలత_t len;
	స్థిరరాశి అక్షరం *endp;

	/* Empty or NULL string gets treated as "." */
	ఒకవేళ (మార్గం == ఖాళీ || *మార్గం == '\0') {
		dname[0] = '.';
		dname[1] = '\0';
		తిరిగి (dname);
	}

	/* Strip any trailing slashes */
	endp = మార్గం + అక్షరశ్రేణి_పొడవు(మార్గం) - 1;
	అయితే (endp > మార్గం && *endp == '/')
		endp--;

	/* Find the start of the dir */
	అయితే (endp > మార్గం && *endp != '/')
		endp--;

	/* Either the dir is "/" or there are no slashes */
	ఒకవేళ (endp == మార్గం) {
		dname[0] = *endp == '/' ? '/' : '.';
		dname[1] = '\0';
		తిరిగి (dname);
	} లేకపోతే {
		/* Move forward past the separating slashes */
		చేయి {
			endp--;
		} అయితే (endp > మార్గం && *endp == '/');
	}

	len = endp - మార్గం + 1;
	ఒకవేళ (len >= పరిమాణం(dname)) {
		errno = ENAMETOOLONG;
		తిరిగి (ఖాళీ);
	}
	జ్ఞాపకం_నకలు(dname, మార్గం, len);
	dname[len] = '\0';
	తిరిగి (dname);
}
#అయితే_ముగింపు
