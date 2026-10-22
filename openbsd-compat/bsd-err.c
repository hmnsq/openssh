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

#ضمن "includes.h"

#ضمن <errno.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#که_نه_تعریف_شوی HAVE_ERR
فراغ
err(صحيح r, ثابت حرف *fmt, ...)
{
	va_list دلیلونه;

	va_start(دلیلونه, fmt);
	fprintf(stderr, "%s: ", strerror(errno));
	vfprintf(stderr, fmt, دلیلونه);
	fputc('\n', stderr);
	va_end(دلیلونه);
	وتل(r);
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_ERRX
فراغ
errx(صحيح r, ثابت حرف *fmt, ...)
{
	va_list دلیلونه;

	va_start(دلیلونه, fmt);
	vfprintf(stderr, fmt, دلیلونه);
	fputc('\n', stderr);
	va_end(دلیلونه);
	وتل(r);
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_WARN
فراغ
warn(ثابت حرف *fmt, ...)
{
	va_list دلیلونه;

	va_start(دلیلونه, fmt);
	fprintf(stderr, "%s: ", strerror(errno));
	vfprintf(stderr, fmt, دلیلونه);
	fputc('\n', stderr);
	va_end(دلیلونه);
}
#د_که_پای
