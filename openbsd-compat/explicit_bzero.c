/* OPENBSD ORIGINAL: lib/libc/string/explicit_bzero.c */
/*	$OpenBSD: explicit_bzero.c,v 1.1 2014/01/22 21:06:45 tedu Exp $ */
/*
 * Public domain.
 * Written by Ted Unangst
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <string.h>

/*
 * explicit_bzero - don't let the compiler optimize away bzero
 */

#నిర్వచితం_కాకపోతే HAVE_EXPLICIT_BZERO

#నిర్వచితమైతే HAVE_EXPLICIT_MEMSET

శూన్య
explicit_bzero(శూన్య *p, కొలత_t n)
{
	(శూన్య)explicit_memset(p, 0, n);
}

#లేదావేళ defined(HAVE_MEMSET_S)

శూన్య
explicit_bzero(శూన్య *p, కొలత_t n)
{
	ఒకవేళ (n == 0)
		తిరిగి;
	(శూన్య)memset_s(p, n, 0, n);
}

#లేకపోతే /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
స్థిర శూన్య (* అస్థిర ssh_bzero)(శూన్య *, కొలత_t) = bzero;

శూన్య
explicit_bzero(శూన్య *p, కొలత_t n)
{
	ఒకవేళ (n == 0)
		తిరిగి;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#ఒకవేళ defined(__has_feature)
# ఒకవేళ __has_feature(జ్ఞాపకం_sanitizer)
	memset(p, 0, n);
# endif
#అయితే_ముగింపు

	ssh_bzero(p, n);
}

#అయితే_ముగింపు /* HAVE_MEMSET_S */

#అయితే_ముగింపు /* HAVE_EXPLICIT_BZERO */
