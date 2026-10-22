/*
 * Copyright (c) 2017 Darren Tucker (dtucker at zip com au).
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

#ضمن "config.h"
#تعریف_رد حافظہ_دیو
#تعریف_رد صفر_حافظہ_دیو
#تعریف_رد realloc

#ضمن <sys/types.h>
#ضمن <stdlib.h>

#إذا defined(HAVE_MALLOC) && HAVE_MALLOC == 0
فراغ *
rpl_malloc(ناپ_t ناپ)
{
	إذا (ناپ == 0)
		ناپ = 1;
	أرجع حافظہ_دیو(ناپ);
}
#جے_انت

#إذا defined(HAVE_CALLOC) && HAVE_CALLOC == 0
فراغ *
rpl_calloc(ناپ_t nmemb, ناپ_t ناپ)
{
	إذا (nmemb == 0)
		nmemb = 1;
	إذا (ناپ == 0)
		ناپ = 1;
	أرجع صفر_حافظہ_دیو(nmemb, ناپ);
}
#جے_انت

#إذا defined (HAVE_REALLOC) && HAVE_REALLOC == 0
فراغ *
rpl_realloc(فراغ *ptr, ناپ_t ناپ)
{
	إذا (ناپ == 0)
		ناپ = 1;
	إذا (ptr == 0)
		أرجع حافظہ_دیو(ناپ);
	أرجع realloc(ptr, ناپ);
}
#جے_انت
