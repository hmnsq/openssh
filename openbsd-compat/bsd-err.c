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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#यदि_अपरिभाषितम् HAVE_ERR
शून्य
err(पूर्णाङ्क r, ध्रुव वर्ण *fmt, ...)
{
	va_list तर्काः;

	va_start(तर्काः, fmt);
	fprintf(stderr, "%s: ", strerror(errno));
	vfprintf(stderr, fmt, तर्काः);
	fputc('\n', stderr);
	va_end(तर्काः);
	निर्गच्छ(r);
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_ERRX
शून्य
errx(पूर्णाङ्क r, ध्रुव वर्ण *fmt, ...)
{
	va_list तर्काः;

	va_start(तर्काः, fmt);
	vfprintf(stderr, fmt, तर्काः);
	fputc('\n', stderr);
	va_end(तर्काः);
	निर्गच्छ(r);
}
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_WARN
शून्य
warn(ध्रुव वर्ण *fmt, ...)
{
	va_list तर्काः;

	va_start(तर्काः, fmt);
	fprintf(stderr, "%s: ", strerror(errno));
	vfprintf(stderr, fmt, तर्काः);
	fputc('\n', stderr);
	va_end(तर्काः);
}
#यदि_अन्तः
