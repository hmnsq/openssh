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

#அந்தர்பாவ "config.h"
#undef malloc
#undef calloc
#undef realloc

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdlib.h>

#எனில் defined(HAVE_MALLOC) && HAVE_MALLOC == 0
வெறுமை *
rpl_malloc(size_t size)
{
	எனில் (size == 0)
		size = 1;
	திரும்பு malloc(size);
}
#endif

#எனில் defined(HAVE_CALLOC) && HAVE_CALLOC == 0
வெறுமை *
rpl_calloc(size_t nmemb, size_t size)
{
	எனில் (nmemb == 0)
		nmemb = 1;
	எனில் (size == 0)
		size = 1;
	திரும்பு calloc(nmemb, size);
}
#endif

#எனில் defined (HAVE_REALLOC) && HAVE_REALLOC == 0
வெறுமை *
rpl_realloc(வெறுமை *ptr, size_t size)
{
	எனில் (size == 0)
		size = 1;
	எனில் (ptr == 0)
		திரும்பு malloc(size);
	திரும்பு realloc(ptr, size);
}
#endif
