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

#شامل "includes.h"

#شامل <stdarg.h>
#شامل <stdint.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "xmalloc.h"
#شامل "log.h"

#اگر defined(__OpenBSD__)
ثابت حرف * ثابت malloc_options = "S";
#اگر_ختم /* __OpenBSD__ */

خالی *
xmalloc(سائز_t سائز)
{
	خالی *ptr;

	اگر (سائز == 0)
		fatal("xmalloc: zero size");
	ptr = حافظہ_دو(سائز);
	اگر (ptr == تہی)
		fatal("xmalloc: out of memory (allocating %zu bytes)", سائز);
	واپس ptr;
}

خالی *
xcalloc(سائز_t nmemb, سائز_t سائز)
{
	خالی *ptr;

	اگر (سائز == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	اگر (SIZE_MAX / nmemb < سائز)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = صفر_حافظہ_دو(nmemb, سائز);
	اگر (ptr == تہی)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    سائز * nmemb);
	واپس ptr;
}

خالی *
xreallocarray(خالی *ptr, سائز_t nmemb, سائز_t سائز)
{
	خالی *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, سائز);
	اگر (new_ptr == تہی)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, سائز);
	واپس new_ptr;
}

خالی *
xrecallocarray(خالی *ptr, سائز_t onmemb, سائز_t nmemb, سائز_t سائز)
{
	خالی *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, سائز);
	اگر (new_ptr == تہی)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, سائز);
	واپس new_ptr;
}

حرف *
xstrdup(ثابت حرف *str)
{
	سائز_t len;
	حرف *cp;

	len = لڑی_لمبائی(str) + 1;
	cp = xmalloc(len);
	واپس حافظہ_نقل(cp, str, len);
}

صحیح
xvasprintf(حرف **ret, ثابت حرف *fmt, va_list ap)
{
	صحیح i;

	i = vasprintf(ret, fmt, ap);
	اگر (i < 0 || *ret == تہی)
		fatal("xvasprintf: could not allocate memory");
	واپس i;
}

صحیح
xasprintf(حرف **ret, ثابت حرف *fmt, ...)
{
	va_list ap;
	صحیح i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	واپس i;
}
