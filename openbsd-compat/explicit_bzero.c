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

#ifndef HAVE_EXPLICIT_BZERO

#ifdef HAVE_EXPLICIT_MEMSET

ಶೂನ್ಯ
explicit_bzero(ಶೂನ್ಯ *p, size_t n)
{
	(ಶೂನ್ಯ)explicit_memset(p, 0, n);
}

#ನೋಚೇದ್ಯದಿ defined(HAVE_MEMSET_S)

ಶೂನ್ಯ
explicit_bzero(ಶೂನ್ಯ *p, size_t n)
{
	ಯದಿ (n == 0)
		ಪ್ರತ್ಯಾಗಮ;
	(ಶೂನ್ಯ)memset_s(p, n, 0, n);
}

#ಅನ್ಯಥಾ /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
ಸ್ಥಿರ ಶೂನ್ಯ (* ಚಞ್ಚಲ ssh_bzero)(ಶೂನ್ಯ *, size_t) = bzero;

ಶೂನ್ಯ
explicit_bzero(ಶೂನ್ಯ *p, size_t n)
{
	ಯದಿ (n == 0)
		ಪ್ರತ್ಯಾಗಮ;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#ಯದಿ defined(__has_feature)
# ಯದಿ __has_feature(memory_sanitizer)
	memset(p, 0, n);
# endif
#endif

	ssh_bzero(p, n);
}

#endif /* HAVE_MEMSET_S */

#endif /* HAVE_EXPLICIT_BZERO */
