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
#تعریف_لغوه حافظه_ورکړه
#تعریف_لغوه حافظه_صفر_ورکړه
#تعریف_لغوه realloc

#ضمن <sys/types.h>
#ضمن <stdlib.h>

#إذا defined(HAVE_MALLOC) && HAVE_MALLOC == 0
فراغ *
rpl_malloc(اندازه_t اندازه)
{
	إذا (اندازه == 0)
		اندازه = 1;
	أرجع حافظه_ورکړه(اندازه);
}
#د_که_پای

#إذا defined(HAVE_CALLOC) && HAVE_CALLOC == 0
فراغ *
rpl_calloc(اندازه_t nmemb, اندازه_t اندازه)
{
	إذا (nmemb == 0)
		nmemb = 1;
	إذا (اندازه == 0)
		اندازه = 1;
	أرجع حافظه_صفر_ورکړه(nmemb, اندازه);
}
#د_که_پای

#إذا defined (HAVE_REALLOC) && HAVE_REALLOC == 0
فراغ *
rpl_realloc(فراغ *ptr, اندازه_t اندازه)
{
	إذا (اندازه == 0)
		اندازه = 1;
	إذا (ptr == 0)
		أرجع حافظه_ورکړه(اندازه);
	أرجع realloc(ptr, اندازه);
}
#د_که_پای
