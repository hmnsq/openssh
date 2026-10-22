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
#undef malloc
#undef calloc
#undef realloc

#ضمن <sys/types.h>
#ضمن <stdlib.h>

#𐤀𐤌 defined(HAVE_MALLOC) && HAVE_MALLOC == 0
فراغ *
rpl_malloc(size_t size)
{
	𐤀𐤌 (size == 0)
		size = 1;
	أرجع malloc(size);
}
#endif

#𐤀𐤌 defined(HAVE_CALLOC) && HAVE_CALLOC == 0
فراغ *
rpl_calloc(size_t nmemb, size_t size)
{
	𐤀𐤌 (nmemb == 0)
		nmemb = 1;
	𐤀𐤌 (size == 0)
		size = 1;
	أرجع calloc(nmemb, size);
}
#endif

#𐤀𐤌 defined (HAVE_REALLOC) && HAVE_REALLOC == 0
فراغ *
rpl_realloc(فراغ *ptr, size_t size)
{
	𐤀𐤌 (size == 0)
		size = 1;
	𐤀𐤌 (ptr == 0)
		أرجع malloc(size);
	أرجع realloc(ptr, size);
}
#endif
