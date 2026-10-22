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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ERR
ਖਾਲੀ
err(ਪੂਰਨ r, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ਦਲੀਲਾਂ;

	va_start(ਦਲੀਲਾਂ, fmt);
	fprintf(stderr, "%s: ", strerror(errno));
	vfprintf(stderr, fmt, ਦਲੀਲਾਂ);
	fputc('\n', stderr);
	va_end(ਦਲੀਲਾਂ);
	ਬਾਹਰ_ਨਿਕਲੋ(r);
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ERRX
ਖਾਲੀ
errx(ਪੂਰਨ r, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ਦਲੀਲਾਂ;

	va_start(ਦਲੀਲਾਂ, fmt);
	vfprintf(stderr, fmt, ਦਲੀਲਾਂ);
	fputc('\n', stderr);
	va_end(ਦਲੀਲਾਂ);
	ਬਾਹਰ_ਨਿਕਲੋ(r);
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_WARN
ਖਾਲੀ
warn(ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ਦਲੀਲਾਂ;

	va_start(ਦਲੀਲਾਂ, fmt);
	fprintf(stderr, "%s: ", strerror(errno));
	vfprintf(stderr, fmt, ਦਲੀਲਾਂ);
	fputc('\n', stderr);
	va_end(ਦਲੀਲਾਂ);
}
#ਜੇ_ਅੰਤ
