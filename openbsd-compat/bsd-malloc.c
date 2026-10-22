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
#अपरिभाषय स्मृतिं_देहि
#अपरिभाषय शून्यस्मृतिं_देहि
#अपरिभाषय realloc

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdlib.h>

#यदि defined(HAVE_MALLOC) && HAVE_MALLOC == 0
शून्य *
rpl_malloc(आकार_t आकार)
{
	यदि (आकार == 0)
		आकार = 1;
	प्रत्यागम स्मृतिं_देहि(आकार);
}
#यदि_अन्तः

#यदि defined(HAVE_CALLOC) && HAVE_CALLOC == 0
शून्य *
rpl_calloc(आकार_t nmemb, आकार_t आकार)
{
	यदि (nmemb == 0)
		nmemb = 1;
	यदि (आकार == 0)
		आकार = 1;
	प्रत्यागम शून्यस्मृतिं_देहि(nmemb, आकार);
}
#यदि_अन्तः

#यदि defined (HAVE_REALLOC) && HAVE_REALLOC == 0
शून्य *
rpl_realloc(शून्य *ptr, आकार_t आकार)
{
	यदि (आकार == 0)
		आकार = 1;
	यदि (ptr == 0)
		प्रत्यागम स्मृतिं_देहि(आकार);
	प्रत्यागम realloc(ptr, आकार);
}
#यदि_अन्तः
