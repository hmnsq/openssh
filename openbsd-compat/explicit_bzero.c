/* OPENBSD ORIGINAL: lib/libc/string/explicit_bzero.c */
/*	$OpenBSD: explicit_bzero.c,v 1.1 2014/01/22 21:06:45 tedu Exp $ */
/*
 * Public domain.
 * Written by Ted Unangst
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

/*
 * explicit_bzero - don't let the compiler optimize away bzero
 */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_EXPLICIT_BZERO

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_EXPLICIT_MEMSET

ਖਾਲੀ
explicit_bzero(ਖਾਲੀ *p, ਮਾਪ_t n)
{
	(ਖਾਲੀ)explicit_memset(p, 0, n);
}

#ਜਾਂਜੇ defined(HAVE_MEMSET_S)

ਖਾਲੀ
explicit_bzero(ਖਾਲੀ *p, ਮਾਪ_t n)
{
	ਜੇ (n == 0)
		ਵਾਪਸ;
	(ਖਾਲੀ)memset_s(p, n, 0, n);
}

#ਨਹੀਂਤਾਂ /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
ਸਥਿਰ ਖਾਲੀ (* ਅਸਥਿਰ ssh_bzero)(ਖਾਲੀ *, ਮਾਪ_t) = bzero;

ਖਾਲੀ
explicit_bzero(ਖਾਲੀ *p, ਮਾਪ_t n)
{
	ਜੇ (n == 0)
		ਵਾਪਸ;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#ਜੇ defined(__has_feature)
# ਜੇ __has_feature(ਸਮ੍ਰਿਤੀ_sanitizer)
	memset(p, 0, n);
# endif
#ਜੇ_ਅੰਤ

	ssh_bzero(p, n);
}

#ਜੇ_ਅੰਤ /* HAVE_MEMSET_S */

#ਜੇ_ਅੰਤ /* HAVE_EXPLICIT_BZERO */
