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

#अन्तर्भाव "config.h"
#undef malloc
#undef calloc
#undef realloc

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdlib.h>

#सचे defined(HAVE_MALLOC) && HAVE_MALLOC == 0
शून्य *
rpl_malloc(size_t size)
{
	सचे (size == 0)
		size = 1;
	पटिनिवत्त malloc(size);
}
#endif

#सचे defined(HAVE_CALLOC) && HAVE_CALLOC == 0
शून्य *
rpl_calloc(size_t nmemb, size_t size)
{
	सचे (nmemb == 0)
		nmemb = 1;
	सचे (size == 0)
		size = 1;
	पटिनिवत्त calloc(nmemb, size);
}
#endif

#सचे defined (HAVE_REALLOC) && HAVE_REALLOC == 0
शून्य *
rpl_realloc(शून्य *ptr, size_t size)
{
	सचे (size == 0)
		size = 1;
	सचे (ptr == 0)
		पटिनिवत्त malloc(size);
	पटिनिवत्त realloc(ptr, size);
}
#endif
