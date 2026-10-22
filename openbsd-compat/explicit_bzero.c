/* OPENBSD ORIGINAL: lib/libc/string/explicit_bzero.c */
/*	$OpenBSD: explicit_bzero.c,v 1.1 2014/01/22 21:06:45 tedu Exp $ */
/*
 * Public domain.
 * Written by Ted Unangst
 */

#include "includes.h"

#include <string.h>

/*
 * explicit_bzero - don't let the compiler optimize away bzero
 */

#ifndef HAVE_EXPLICIT_BZERO

#ifdef HAVE_EXPLICIT_MEMSET

void
explicit_bzero(void *p, size_t n)
{
	(void)explicit_memset(p, 0, n);
}

#elif defined(HAVE_MEMSET_S)

void
explicit_bzero(void *p, size_t n)
{
	အကယ်၍ (n == 0)
		ပြန်ပေး;
	(void)memset_s(p, n, 0, n);
}

#မဟုတ်ပါက /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
static void (* ca_ncala ssh_bzero)(void *, size_t) = bzero;

void
explicit_bzero(void *p, size_t n)
{
	အကယ်၍ (n == 0)
		ပြန်ပေး;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#အကယ်၍ defined(__has_feature)
# အကယ်၍ __has_feature(memory_sanitizer)
	memset(p, 0, n);
# endif
#endif

	ssh_bzero(p, n);
}

#endif /* HAVE_MEMSET_S */

#endif /* HAVE_EXPLICIT_BZERO */
