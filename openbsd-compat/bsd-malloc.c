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

#ಅನ್ತರ್ಭಾವ "config.h"
#undef malloc
#undef calloc
#undef realloc

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

#ಯದಿ defined(HAVE_MALLOC) && HAVE_MALLOC == 0
ಶೂನ್ಯ *
rpl_malloc(size_t size)
{
	ಯದಿ (size == 0)
		size = 1;
	ಪ್ರತ್ಯಾಗಮ malloc(size);
}
#endif

#ಯದಿ defined(HAVE_CALLOC) && HAVE_CALLOC == 0
ಶೂನ್ಯ *
rpl_calloc(size_t nmemb, size_t size)
{
	ಯದಿ (nmemb == 0)
		nmemb = 1;
	ಯದಿ (size == 0)
		size = 1;
	ಪ್ರತ್ಯಾಗಮ calloc(nmemb, size);
}
#endif

#ಯದಿ defined (HAVE_REALLOC) && HAVE_REALLOC == 0
ಶೂನ್ಯ *
rpl_realloc(ಶೂನ್ಯ *ptr, size_t size)
{
	ಯದಿ (size == 0)
		size = 1;
	ಯದಿ (ptr == 0)
		ಪ್ರತ್ಯಾಗಮ malloc(size);
	ಪ್ರತ್ಯಾಗಮ realloc(ptr, size);
}
#endif
