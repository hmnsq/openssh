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
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ಸ್ಮರಣೆ_ಕೊಡು
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು realloc

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

#ಆದರೆ defined(HAVE_MALLOC) && HAVE_MALLOC == 0
ಶೂನ್ಯ *
rpl_malloc(ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಆದರೆ (ಗಾತ್ರ_2 == 0)
		ಗಾತ್ರ_2 = 1;
	ಹಿಂತಿರುಗಿ ಸ್ಮರಣೆ_ಕೊಡು(ಗಾತ್ರ_2);
}
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_CALLOC) && HAVE_CALLOC == 0
ಶೂನ್ಯ *
rpl_calloc(ಗಾತ್ರ_t nmemb, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಆದರೆ (nmemb == 0)
		nmemb = 1;
	ಆದರೆ (ಗಾತ್ರ_2 == 0)
		ಗಾತ್ರ_2 = 1;
	ಹಿಂತಿರುಗಿ ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(nmemb, ಗಾತ್ರ_2);
}
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined (HAVE_REALLOC) && HAVE_REALLOC == 0
ಶೂನ್ಯ *
rpl_realloc(ಶೂನ್ಯ *ptr, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಆದರೆ (ಗಾತ್ರ_2 == 0)
		ಗಾತ್ರ_2 = 1;
	ಆದರೆ (ptr == 0)
		ಹಿಂತಿರುಗಿ ಸ್ಮರಣೆ_ಕೊಡು(ಗಾತ್ರ_2);
	ಹಿಂತಿರುಗಿ realloc(ptr, ಗಾತ್ರ_2);
}
#ಆದರೆ_ಅಂತ್ಯ
