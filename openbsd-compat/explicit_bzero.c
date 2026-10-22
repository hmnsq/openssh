/* OPENBSD ORIGINAL: lib/libc/string/explicit_bzero.c */
/*	$OpenBSD: explicit_bzero.c,v 1.1 2014/01/22 21:06:45 tedu Exp $ */
/*
 * Public domain.
 * Written by Ted Unangst
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <string.h>

/*
 * explicit_bzero - don't let the compiler optimize away bzero
 */

#ifndef HAVE_EXPLICIT_BZERO

#ifdef HAVE_EXPLICIT_MEMSET

शून्य
explicit_bzero(शून्य *p, size_t n)
{
	(शून्य)explicit_memset(p, 0, n);
}

#नोचेद्यदि defined(HAVE_MEMSET_S)

शून्य
explicit_bzero(शून्य *p, size_t n)
{
	जइ (n == 0)
		प्रत्यागम;
	(शून्य)memset_s(p, n, 0, n);
}

#अण्णहा /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
स्थिर शून्य (* चञ्चल ssh_bzero)(शून्य *, size_t) = bzero;

शून्य
explicit_bzero(शून्य *p, size_t n)
{
	जइ (n == 0)
		प्रत्यागम;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#जइ defined(__has_feature)
# जइ __has_feature(memory_sanitizer)
	memset(p, 0, n);
# endif
#endif

	ssh_bzero(p, n);
}

#endif /* HAVE_MEMSET_S */

#endif /* HAVE_EXPLICIT_BZERO */
