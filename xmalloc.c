/* $OpenBSD: xmalloc.c,v 1.38 2025/05/23 00:40:45 deraadt Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Versions of malloc and friends that check their results, and never return
 * failure (they call fatal if they encounter an error).
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ضمن "includes.h"

#ضمن <stdarg.h>
#ضمن <stdint.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "xmalloc.h"
#ضمن "log.h"

#إذا defined(__OpenBSD__)
ثابت حرف * ثابت malloc_options = "S";
#د_که_پای /* __OpenBSD__ */

فراغ *
xmalloc(اندازه_t اندازه)
{
	فراغ *ptr;

	إذا (اندازه == 0)
		fatal("xmalloc: zero size");
	ptr = حافظه_ورکړه(اندازه);
	إذا (ptr == عدم)
		fatal("xmalloc: out of memory (allocating %zu bytes)", اندازه);
	أرجع ptr;
}

فراغ *
xcalloc(اندازه_t nmemb, اندازه_t اندازه)
{
	فراغ *ptr;

	إذا (اندازه == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	إذا (SIZE_MAX / nmemb < اندازه)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = حافظه_صفر_ورکړه(nmemb, اندازه);
	إذا (ptr == عدم)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    اندازه * nmemb);
	أرجع ptr;
}

فراغ *
xreallocarray(فراغ *ptr, اندازه_t nmemb, اندازه_t اندازه)
{
	فراغ *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, اندازه);
	إذا (new_ptr == عدم)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, اندازه);
	أرجع new_ptr;
}

فراغ *
xrecallocarray(فراغ *ptr, اندازه_t onmemb, اندازه_t nmemb, اندازه_t اندازه)
{
	فراغ *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, اندازه);
	إذا (new_ptr == عدم)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, اندازه);
	أرجع new_ptr;
}

حرف *
xstrdup(ثابت حرف *str)
{
	اندازه_t len;
	حرف *cp;

	len = مزي_اوږدوالی(str) + 1;
	cp = xmalloc(len);
	أرجع حافظه_نقل(cp, str, len);
}

صحيح
xvasprintf(حرف **ret, ثابت حرف *fmt, va_list ap)
{
	صحيح i;

	i = vasprintf(ret, fmt, ap);
	إذا (i < 0 || *ret == عدم)
		fatal("xvasprintf: could not allocate memory");
	أرجع i;
}

صحيح
xasprintf(حرف **ret, ثابت حرف *fmt, ...)
{
	va_list ap;
	صحيح i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	أرجع i;
}
