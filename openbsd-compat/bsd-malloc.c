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

#ଅନ୍ତର୍ଭାଵ "config.h"
#undef malloc
#undef calloc
#undef realloc

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>

#ଯଦି defined(HAVE_MALLOC) && HAVE_MALLOC == 0
ଶୂନ୍ୟ *
rpl_malloc(size_t size)
{
	ଯଦି (size == 0)
		size = 1;
	ଫେରନ୍ତୁ malloc(size);
}
#endif

#ଯଦି defined(HAVE_CALLOC) && HAVE_CALLOC == 0
ଶୂନ୍ୟ *
rpl_calloc(size_t nmemb, size_t size)
{
	ଯଦି (nmemb == 0)
		nmemb = 1;
	ଯଦି (size == 0)
		size = 1;
	ଫେରନ୍ତୁ calloc(nmemb, size);
}
#endif

#ଯଦି defined (HAVE_REALLOC) && HAVE_REALLOC == 0
ଶୂନ୍ୟ *
rpl_realloc(ଶୂନ୍ୟ *ptr, size_t size)
{
	ଯଦି (size == 0)
		size = 1;
	ଯଦି (ptr == 0)
		ଫେରନ୍ତୁ malloc(size);
	ଫେରନ୍ତୁ realloc(ptr, size);
}
#endif
