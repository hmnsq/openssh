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
#وصف_رد يادگيري_ڏيو
#وصف_رد صفر_يادگيري_ڏيو
#وصف_رد realloc

#ضمن <sys/types.h>
#ضمن <stdlib.h>

#إذا defined(HAVE_MALLOC) && HAVE_MALLOC == 0
فراغ *
rpl_malloc(سائيز_t سائيز)
{
	إذا (سائيز == 0)
		سائيز = 1;
	أرجع يادگيري_ڏيو(سائيز);
}
#جيڪڏهن_پورو

#إذا defined(HAVE_CALLOC) && HAVE_CALLOC == 0
فراغ *
rpl_calloc(سائيز_t nmemb, سائيز_t سائيز)
{
	إذا (nmemb == 0)
		nmemb = 1;
	إذا (سائيز == 0)
		سائيز = 1;
	أرجع صفر_يادگيري_ڏيو(nmemb, سائيز);
}
#جيڪڏهن_پورو

#إذا defined (HAVE_REALLOC) && HAVE_REALLOC == 0
فراغ *
rpl_realloc(فراغ *ptr, سائيز_t سائيز)
{
	إذا (سائيز == 0)
		سائيز = 1;
	إذا (ptr == 0)
		أرجع يادگيري_ڏيو(سائيز);
	أرجع realloc(ptr, سائيز);
}
#جيڪڏهن_پورو
