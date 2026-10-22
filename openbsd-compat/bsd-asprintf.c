/*
 * Copyright (c) 2004 Darren Tucker.
 *
 * Based originally on asprintf.c from OpenBSD:
 * Copyright (c) 1997 Todd C. Miller <Todd.Miller@courtesan.com>
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

/*
 * Don't let systems with broken printf(3) avoid our replacements
 * via asprintf(3)/vasprintf(3) calling libc internally.
 */
#ఒకవేళ defined(BROKEN_SNPRINTF)
# undef HAVE_VASPRINTF
# undef HAVE_ASPRINTF
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_VASPRINTF

#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>

#నిర్వచించు INIT_SZ	128

పూర్ణాంకం
vasprintf(అక్షరం **str, స్థిరరాశి అక్షరం *fmt, va_list ap)
{
	పూర్ణాంకం ret = -1;
	va_list ap2;
	అక్షరం *string, *newstr;
	కొలత_t len;

	VA_COPY(ap2, ap);
	ఒకవేళ ((string = జ్ఞాపకం_ఇవ్వు(INIT_SZ)) == ఖాళీ)
		వెళ్ళు fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	ఒకవేళ (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} లేకపోతే ఒకవేళ (ret == గరిష్ఠ_పూర్ణాంకం || ret < 0) { /* Bad length */
		విడుదల(string);
		వెళ్ళు fail;
	} లేకపోతే {	/* bigger than initial, realloc allowing for nul */
		len = (కొలత_t)ret + 1;
		ఒకవేళ ((newstr = realloc(string, len)) == ఖాళీ) {
			విడుదల(string);
			వెళ్ళు fail;
		} లేకపోతే {
			va_end(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			ఒకవేళ (ret >= 0 && (కొలత_t)ret < len) {
				*str = newstr;
			} లేకపోతే { /* failed with realloc'ed string, give up */
				విడుదల(newstr);
				వెళ్ళు fail;
			}
		}
	}
	va_end(ap2);
	తిరిగి (ret);

fail:
	*str = ఖాళీ;
	errno = ENOMEM;
	va_end(ap2);
	తిరిగి (-1);
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_ASPRINTF
పూర్ణాంకం asprintf(అక్షరం **str, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list ap;
	పూర్ణాంకం ret;

	*str = ఖాళీ;
	va_start(ap, fmt);
	ret = vasprintf(str, fmt, ap);
	va_end(ap);

	తిరిగి ret;
}
#అయితే_ముగింపు
