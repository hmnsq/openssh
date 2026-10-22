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

#অন্তর্ভাৱ "config.h"
#undef malloc
#undef calloc
#undef realloc

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <stdlib.h>

#যদি defined(HAVE_MALLOC) && HAVE_MALLOC == 0
শূন্য *
rpl_malloc(size_t size)
{
	যদি (size == 0)
		size = 1;
	ঘূৰাই malloc(size);
}
#endif

#যদি defined(HAVE_CALLOC) && HAVE_CALLOC == 0
শূন্য *
rpl_calloc(size_t nmemb, size_t size)
{
	যদি (nmemb == 0)
		nmemb = 1;
	যদি (size == 0)
		size = 1;
	ঘূৰাই calloc(nmemb, size);
}
#endif

#যদি defined (HAVE_REALLOC) && HAVE_REALLOC == 0
শূন্য *
rpl_realloc(শূন্য *ptr, size_t size)
{
	যদি (size == 0)
		size = 1;
	যদি (ptr == 0)
		ঘূৰাই malloc(size);
	ঘূৰাই realloc(ptr, size);
}
#endif
