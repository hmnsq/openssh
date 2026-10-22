/* OPENBSD ORIGINAL: lib/libc/string/explicit_bzero.c */
/*	$OpenBSD: explicit_bzero.c,v 1.1 2014/01/22 21:06:45 tedu Exp $ */
/*
 * Public domain.
 * Written by Ted Unangst
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <string.h>

/*
 * explicit_bzero - don't let the compiler optimize away bzero
 */

#ifndef HAVE_EXPLICIT_BZERO

#ifdef HAVE_EXPLICIT_MEMSET

શૂન્ય
explicit_bzero(શૂન્ય *p, size_t n)
{
	(શૂન્ય)explicit_memset(p, 0, n);
}

#અથવાજો defined(HAVE_MEMSET_S)

શૂન્ય
explicit_bzero(શૂન્ય *p, size_t n)
{
	જો (n == 0)
		પાછા;
	(શૂન્ય)memset_s(p, n, 0, n);
}

#નહીંતર /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
સ્થિર શૂન્ય (* અસ્થિર ssh_bzero)(શૂન્ય *, size_t) = bzero;

શૂન્ય
explicit_bzero(શૂન્ય *p, size_t n)
{
	જો (n == 0)
		પાછા;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#જો defined(__has_feature)
# જો __has_feature(memory_sanitizer)
	memset(p, 0, n);
# endif
#endif

	ssh_bzero(p, n);
}

#endif /* HAVE_MEMSET_S */

#endif /* HAVE_EXPLICIT_BZERO */
