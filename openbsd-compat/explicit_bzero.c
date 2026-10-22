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
explicit_bzero(शून्य *p, माप_प्रकार n)
{
	(शून्य)explicit_memset(p, 0, n);
}

#अथवायदि defined(HAVE_MEMSET_S)

शून्य
explicit_bzero(शून्य *p, माप_प्रकार n)
{
	यदि (n == 0)
		फर्काऊ;
	(शून्य)memset_s(p, n, 0, n);
}

#अन्यथा /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
स्थिर शून्य (* चञ्चल ssh_bzero)(शून्य *, माप_प्रकार) = bzero;

शून्य
explicit_bzero(शून्य *p, माप_प्रकार n)
{
	यदि (n == 0)
		फर्काऊ;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#यदि defined(__has_feature)
# यदि __has_feature(memory_sanitizer)
	स_रखो(p, 0, n);
# endif
#endif

	ssh_bzero(p, n);
}

#endif /* HAVE_MEMSET_S */

#endif /* HAVE_EXPLICIT_BZERO */
