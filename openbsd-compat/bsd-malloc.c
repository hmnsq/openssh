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

#समावेश "config.h"
#अघोषित दो_स्मृति
#अघोषित सुस्मृति
#अघोषित पुनः_स्मृति

#समावेश <sys/types.h>
#समावेश <stdlib.h>

#अगर defined(HAVE_MALLOC) && HAVE_MALLOC == 0
व्योम *
rpl_malloc(माप_प्रकार आकार)
{
	अगर (आकार == 0)
		आकार = 1;
	वापस दो_स्मृति(आकार);
}
#पूर्ण_अगर

#अगर defined(HAVE_CALLOC) && HAVE_CALLOC == 0
व्योम *
rpl_calloc(माप_प्रकार nmemb, माप_प्रकार आकार)
{
	अगर (nmemb == 0)
		nmemb = 1;
	अगर (आकार == 0)
		आकार = 1;
	वापस सुस्मृति(nmemb, आकार);
}
#पूर्ण_अगर

#अगर defined (HAVE_REALLOC) && HAVE_REALLOC == 0
व्योम *
rpl_realloc(व्योम *ptr, माप_प्रकार आकार)
{
	अगर (आकार == 0)
		आकार = 1;
	अगर (ptr == 0)
		वापस दो_स्मृति(आकार);
	वापस पुनः_स्मृति(ptr, आकार);
}
#पूर्ण_अगर
