/* OPENBSD ORIGINAL: lib/libc/string/explicit_bzero.c */
/*	$OpenBSD: explicit_bzero.c,v 1.1 2014/01/22 21:06:45 tedu Exp $ */
/*
 * Public domain.
 * Written by Ted Unangst
 */

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <string.h>

/*
 * explicit_bzero - don't let the compiler optimize away bzero
 */

#ifndef HAVE_EXPLICIT_BZERO

#ifdef HAVE_EXPLICIT_MEMSET

শূন্য
explicit_bzero(শূন্য *p, size_t n)
{
	(শূন্য)explicit_memset(p, 0, n);
}

#নোচেদ্যদি defined(HAVE_MEMSET_S)

শূন্য
explicit_bzero(শূন্য *p, size_t n)
{
	যদি (n == 0)
		ঘূৰাই;
	(শূন্য)memset_s(p, n, 0, n);
}

#অন্যথা /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
স্থির শূন্য (* চঞ্চল ssh_bzero)(শূন্য *, size_t) = bzero;

শূন্য
explicit_bzero(শূন্য *p, size_t n)
{
	যদি (n == 0)
		ঘূৰাই;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#যদি defined(__has_feature)
# যদি __has_feature(memory_sanitizer)
	memset(p, 0, n);
# endif
#endif

	ssh_bzero(p, n);
}

#endif /* HAVE_MEMSET_S */

#endif /* HAVE_EXPLICIT_BZERO */
