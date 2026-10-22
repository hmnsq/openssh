/*
 * Copyright (c) 2015 Tim Rice <tim@multitalents.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#నిర్వచితం_కాకపోతే HAVE_ERR
శూన్య
err(పూర్ణాంకం r, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list వాదనలు;

	va_start(వాదనలు, fmt);
	fprintf(stderr, "%s: ", strerror(errno));
	vfprintf(stderr, fmt, వాదనలు);
	fputc('\n', stderr);
	va_end(వాదనలు);
	నిష్క్రమించు(r);
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_ERRX
శూన్య
errx(పూర్ణాంకం r, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list వాదనలు;

	va_start(వాదనలు, fmt);
	vfprintf(stderr, fmt, వాదనలు);
	fputc('\n', stderr);
	va_end(వాదనలు);
	నిష్క్రమించు(r);
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_WARN
శూన్య
warn(స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list వాదనలు;

	va_start(వాదనలు, fmt);
	fprintf(stderr, "%s: ", strerror(errno));
	vfprintf(stderr, fmt, వాదనలు);
	fputc('\n', stderr);
	va_end(వాదనలు);
}
#అయితే_ముగింపు
