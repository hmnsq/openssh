/* OPENBSD ORIGINAL: lib/libc/string/explicit_bzero.c */
/*	$OpenBSD: explicit_bzero.c,v 1.1 2014/01/22 21:06:45 tedu Exp $ */
/*
 * Public domain.
 * Written by Ted Unangst
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <string.h>

/*
 * explicit_bzero - don't let the compiler optimize away bzero
 */

#ifndef HAVE_EXPLICIT_BZERO

#ifdef HAVE_EXPLICIT_MEMSET

ശൂന്യം
explicit_bzero(ശൂന്യം *p, size_t n)
{
	(ശൂന്യം)explicit_memset(p, 0, n);
}

#അല്ലെങ്കിലെങ്കിൽ defined(HAVE_MEMSET_S)

ശൂന്യം
explicit_bzero(ശൂന്യം *p, size_t n)
{
	എങ്കിൽ (n == 0)
		തിരികെ;
	(ശൂന്യം)memset_s(p, n, 0, n);
}

#അല്ലെങ്കിൽ /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
സ്ഥിതം ശൂന്യം (* അസ്ഥിര ssh_bzero)(ശൂന്യം *, size_t) = bzero;

ശൂന്യം
explicit_bzero(ശൂന്യം *p, size_t n)
{
	എങ്കിൽ (n == 0)
		തിരികെ;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#എങ്കിൽ defined(__has_feature)
# എങ്കിൽ __has_feature(memory_sanitizer)
	memset(p, 0, n);
# endif
#endif

	ssh_bzero(p, n);
}

#endif /* HAVE_MEMSET_S */

#endif /* HAVE_EXPLICIT_BZERO */
