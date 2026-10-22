/* OPENBSD ORIGINAL: lib/libc/string/explicit_bzero.c */
/*	$OpenBSD: explicit_bzero.c,v 1.1 2014/01/22 21:06:45 tedu Exp $ */
/*
 * Public domain.
 * Written by Ted Unangst
 */

#شامل "includes.h"

#شامل <string.h>

/*
 * explicit_bzero - don't let the compiler optimize away bzero
 */

#ifndef HAVE_EXPLICIT_BZERO

#ifdef HAVE_EXPLICIT_MEMSET

تهی
explicit_bzero(تهی *p, size_t n)
{
	(تهی)explicit_memset(p, 0, n);
}

#وگرنهاگر defined(HAVE_MEMSET_S)

تهی
explicit_bzero(تهی *p, size_t n)
{
	اگر (n == 0)
		بازگشت;
	(تهی)memset_s(p, n, 0, n);
}

#وگرنه /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
ایستا تهی (* فرار ssh_bzero)(تهی *, size_t) = bzero;

تهی
explicit_bzero(تهی *p, size_t n)
{
	اگر (n == 0)
		بازگشت;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#اگر defined(__has_feature)
# اگر __has_feature(memory_sanitizer)
	memset(p, 0, n);
# endif
#endif

	ssh_bzero(p, n);
}

#endif /* HAVE_MEMSET_S */

#endif /* HAVE_EXPLICIT_BZERO */
