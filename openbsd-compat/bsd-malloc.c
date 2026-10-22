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

#شامل "config.h"
#تعریف_منسوخ حافظہ_دو
#تعریف_منسوخ صفر_حافظہ_دو
#تعریف_منسوخ realloc

#شامل <sys/types.h>
#شامل <stdlib.h>

#اگر defined(HAVE_MALLOC) && HAVE_MALLOC == 0
خالی *
rpl_malloc(سائز_t سائز)
{
	اگر (سائز == 0)
		سائز = 1;
	واپس حافظہ_دو(سائز);
}
#اگر_ختم

#اگر defined(HAVE_CALLOC) && HAVE_CALLOC == 0
خالی *
rpl_calloc(سائز_t nmemb, سائز_t سائز)
{
	اگر (nmemb == 0)
		nmemb = 1;
	اگر (سائز == 0)
		سائز = 1;
	واپس صفر_حافظہ_دو(nmemb, سائز);
}
#اگر_ختم

#اگر defined (HAVE_REALLOC) && HAVE_REALLOC == 0
خالی *
rpl_realloc(خالی *ptr, سائز_t سائز)
{
	اگر (سائز == 0)
		سائز = 1;
	اگر (ptr == 0)
		واپس حافظہ_دو(سائز);
	واپس realloc(ptr, سائز);
}
#اگر_ختم
