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

#ਅਨ੍ਤਰ੍ਭਾਵ "config.h"
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ਸਮ੍ਰਿਤੀ_ਦਿਓ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ realloc

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>

#ਜੇ defined(HAVE_MALLOC) && HAVE_MALLOC == 0
ਖਾਲੀ *
rpl_malloc(ਮਾਪ_t ਮਾਪ)
{
	ਜੇ (ਮਾਪ == 0)
		ਮਾਪ = 1;
	ਵਾਪਸ ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਮਾਪ);
}
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_CALLOC) && HAVE_CALLOC == 0
ਖਾਲੀ *
rpl_calloc(ਮਾਪ_t nmemb, ਮਾਪ_t ਮਾਪ)
{
	ਜੇ (nmemb == 0)
		nmemb = 1;
	ਜੇ (ਮਾਪ == 0)
		ਮਾਪ = 1;
	ਵਾਪਸ ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(nmemb, ਮਾਪ);
}
#ਜੇ_ਅੰਤ

#ਜੇ defined (HAVE_REALLOC) && HAVE_REALLOC == 0
ਖਾਲੀ *
rpl_realloc(ਖਾਲੀ *ptr, ਮਾਪ_t ਮਾਪ)
{
	ਜੇ (ਮਾਪ == 0)
		ਮਾਪ = 1;
	ਜੇ (ptr == 0)
		ਵਾਪਸ ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਮਾਪ);
	ਵਾਪਸ realloc(ptr, ਮਾਪ);
}
#ਜੇ_ਅੰਤ
