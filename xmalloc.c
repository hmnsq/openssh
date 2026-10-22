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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#ಆದರೆ defined(__OpenBSD__)
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ malloc_options = "S";
#ಆದರೆ_ಅಂತ್ಯ /* __OpenBSD__ */

ಶೂನ್ಯ *
xmalloc(ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಶೂನ್ಯ *ptr;

	ಆದರೆ (ಗಾತ್ರ_2 == 0)
		fatal("xmalloc: zero size");
	ptr = ಸ್ಮರಣೆ_ಕೊಡು(ಗಾತ್ರ_2);
	ಆದರೆ (ptr == ಖಾಲಿ)
		fatal("xmalloc: out of memory (allocating %zu bytes)", ಗಾತ್ರ_2);
	ಹಿಂತಿರುಗಿ ptr;
}

ಶೂನ್ಯ *
xcalloc(ಗಾತ್ರ_t nmemb, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಶೂನ್ಯ *ptr;

	ಆದರೆ (ಗಾತ್ರ_2 == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	ಆದರೆ (SIZE_MAX / nmemb < ಗಾತ್ರ_2)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(nmemb, ಗಾತ್ರ_2);
	ಆದರೆ (ptr == ಖಾಲಿ)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    ಗಾತ್ರ_2 * nmemb);
	ಹಿಂತಿರುಗಿ ptr;
}

ಶೂನ್ಯ *
xreallocarray(ಶೂನ್ಯ *ptr, ಗಾತ್ರ_t nmemb, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಶೂನ್ಯ *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, ಗಾತ್ರ_2);
	ಆದರೆ (new_ptr == ಖಾಲಿ)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, ಗಾತ್ರ_2);
	ಹಿಂತಿರುಗಿ new_ptr;
}

ಶೂನ್ಯ *
xrecallocarray(ಶೂನ್ಯ *ptr, ಗಾತ್ರ_t onmemb, ಗಾತ್ರ_t nmemb, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಶೂನ್ಯ *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, ಗಾತ್ರ_2);
	ಆದರೆ (new_ptr == ಖಾಲಿ)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, ಗಾತ್ರ_2);
	ಹಿಂತಿರುಗಿ new_ptr;
}

ಅಕ್ಷರ *
xstrdup(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str)
{
	ಗಾತ್ರ_t len;
	ಅಕ್ಷರ *cp;

	len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(str) + 1;
	cp = xmalloc(len);
	ಹಿಂತಿರುಗಿ ಸ್ಮರಣೆ_ನಕಲು(cp, str, len);
}

ಪೂರ್ಣಾಂಕ
xvasprintf(ಅಕ್ಷರ **ret, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, va_list ap)
{
	ಪೂರ್ಣಾಂಕ i;

	i = vasprintf(ret, fmt, ap);
	ಆದರೆ (i < 0 || *ret == ಖಾಲಿ)
		fatal("xvasprintf: could not allocate memory");
	ಹಿಂತಿರುಗಿ i;
}

ಪೂರ್ಣಾಂಕ
xasprintf(ಅಕ್ಷರ **ret, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list ap;
	ಪೂರ್ಣಾಂಕ i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);
	ಹಿಂತಿರುಗಿ i;
}
