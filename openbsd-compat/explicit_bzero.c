/* OPENBSD ORIGINAL: lib/libc/string/explicit_bzero.c */
/*	$OpenBSD: explicit_bzero.c,v 1.1 2014/01/22 21:06:45 tedu Exp $ */
/*
 * Public domain.
 * Written by Ted Unangst
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <string.h>

/*
 * explicit_bzero - don't let the compiler optimize away bzero
 */

#ifndef HAVE_EXPLICIT_BZERO

#ifdef HAVE_EXPLICIT_MEMSET

வெறுமை
explicit_bzero(வெறுமை *p, size_t n)
{
	(வெறுமை)explicit_memset(p, 0, n);
}

#அல்லதெனில் defined(HAVE_MEMSET_S)

வெறுமை
explicit_bzero(வெறுமை *p, size_t n)
{
	எனில் (n == 0)
		திரும்பு;
	(வெறுமை)memset_s(p, n, 0, n);
}

#இல்லையெனில் /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
நிலையான வெறுமை (* நிலையற்ற ssh_bzero)(வெறுமை *, size_t) = bzero;

வெறுமை
explicit_bzero(வெறுமை *p, size_t n)
{
	எனில் (n == 0)
		திரும்பு;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#எனில் defined(__has_feature)
# எனில் __has_feature(memory_sanitizer)
	memset(p, 0, n);
# endif
#endif

	ssh_bzero(p, n);
}

#endif /* HAVE_MEMSET_S */

#endif /* HAVE_EXPLICIT_BZERO */
