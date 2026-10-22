/* OPENBSD ORIGINAL: lib/libc/string/explicit_bzero.c */
/*	$OpenBSD: explicit_bzero.c,v 1.1 2014/01/22 21:06:45 tedu Exp $ */
/*
 * Public domain.
 * Written by Ted Unangst
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <string.h>

/*
 * explicit_bzero - don't let the compiler optimize away bzero
 */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_EXPLICIT_BZERO

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_EXPLICIT_MEMSET

ಶೂನ್ಯ
explicit_bzero(ಶೂನ್ಯ *p, ಗಾತ್ರ_t n)
{
	(ಶೂನ್ಯ)explicit_memset(p, 0, n);
}

#ಅಥವಾಆದರೆ defined(HAVE_MEMSET_S)

ಶೂನ್ಯ
explicit_bzero(ಶೂನ್ಯ *p, ಗಾತ್ರ_t n)
{
	ಆದರೆ (n == 0)
		ಹಿಂತಿರುಗಿ;
	(ಶೂನ್ಯ)memset_s(p, n, 0, n);
}

#ಇಲ್ಲದಿದ್ದರೆ /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
ಸ್ಥಿರ ಶೂನ್ಯ (* ಅಸ್ಥಿರ ssh_bzero)(ಶೂನ್ಯ *, ಗಾತ್ರ_t) = bzero;

ಶೂನ್ಯ
explicit_bzero(ಶೂನ್ಯ *p, ಗಾತ್ರ_t n)
{
	ಆದರೆ (n == 0)
		ಹಿಂತಿರುಗಿ;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#ಆದರೆ defined(__has_feature)
# ಆದರೆ __has_feature(ಸ್ಮರಣೆ_sanitizer)
	memset(p, 0, n);
# endif
#ಆದರೆ_ಅಂತ್ಯ

	ssh_bzero(p, n);
}

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_MEMSET_S */

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_EXPLICIT_BZERO */
