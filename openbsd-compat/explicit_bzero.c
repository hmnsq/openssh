/* OPENBSD ORIGINAL: lib/libc/string/explicit_bzero.c */
/*	$OpenBSD: explicit_bzero.c,v 1.1 2014/01/22 21:06:45 tedu Exp $ */
/*
 * Public domain.
 * Written by Ted Unangst
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <string.h>

/*
 * explicit_bzero - don't let the compiler optimize away bzero
 */

#ifndef HAVE_EXPLICIT_BZERO

#ifdef HAVE_EXPLICIT_MEMSET

ଶୂନ୍ୟ
explicit_bzero(ଶୂନ୍ୟ *p, size_t n)
{
	(ଶୂନ୍ୟ)explicit_memset(p, 0, n);
}

#ନଚେତଯଦି defined(HAVE_MEMSET_S)

ଶୂନ୍ୟ
explicit_bzero(ଶୂନ୍ୟ *p, size_t n)
{
	ଯଦି (n == 0)
		ଫେରନ୍ତୁ;
	(ଶୂନ୍ୟ)memset_s(p, n, 0, n);
}

#ଅନ୍ୟଥା /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
ସ୍ଥିର ଶୂନ୍ୟ (* ଅସ୍ଥିର ssh_bzero)(ଶୂନ୍ୟ *, size_t) = bzero;

ଶୂନ୍ୟ
explicit_bzero(ଶୂନ୍ୟ *p, size_t n)
{
	ଯଦି (n == 0)
		ଫେରନ୍ତୁ;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#ଯଦି defined(__has_feature)
# ଯଦି __has_feature(memory_sanitizer)
	memset(p, 0, n);
# endif
#endif

	ssh_bzero(p, n);
}

#endif /* HAVE_MEMSET_S */

#endif /* HAVE_EXPLICIT_BZERO */
