/* OPENBSD ORIGINAL: lib/libc/string/explicit_bzero.c */
/*	$OpenBSD: explicit_bzero.c,v 1.1 2014/01/22 21:06:45 tedu Exp $ */
/*
 * Public domain.
 * Written by Ted Unangst
 */

#समावेश "includes.h"

#समावेश <string.h>

/*
 * explicit_bzero - don't let the compiler optimize away bzero
 */

#अगर_अघोषित HAVE_EXPLICIT_BZERO

#अगर_घोषित HAVE_EXPLICIT_MEMSET

व्योम
explicit_bzero(व्योम *p, माप_प्रकार n)
{
	(व्योम)explicit_memset(p, 0, n);
}

#या_अगर defined(HAVE_MEMSET_S)

व्योम
explicit_bzero(व्योम *p, माप_प्रकार n)
{
	अगर (n == 0)
		वापस;
	(व्योम)memset_s(p, n, 0, n);
}

#अन्यथा /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
अटल व्योम (* अस्थिर ssh_bzero)(व्योम *, माप_प्रकार) = bzero;

व्योम
explicit_bzero(व्योम *p, माप_प्रकार n)
{
	अगर (n == 0)
		वापस;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#अगर defined(__has_feature)
# अगर __has_feature(memory_sanitizer)
	स_रखो(p, 0, n);
# endif
#पूर्ण_अगर

	ssh_bzero(p, n);
}

#पूर्ण_अगर /* HAVE_MEMSET_S */

#पूर्ण_अगर /* HAVE_EXPLICIT_BZERO */
