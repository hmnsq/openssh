/* OPENBSD ORIGINAL: lib/libc/string/explicit_bzero.c */
/*	$OpenBSD: explicit_bzero.c,v 1.1 2014/01/22 21:06:45 tedu Exp $ */
/*
 * Public domain.
 * Written by Ted Unangst
 */

#ضمن "includes.h"

#ضمن <string.h>

/*
 * explicit_bzero - don't let the compiler optimize away bzero
 */

#جے_بنا_تعریف HAVE_EXPLICIT_BZERO

#جے_تعریف_شدہ HAVE_EXPLICIT_MEMSET

فراغ
explicit_bzero(فراغ *p, ناپ_t n)
{
	(فراغ)explicit_memset(p, 0, n);
}

#وإلاإذا defined(HAVE_MEMSET_S)

فراغ
explicit_bzero(فراغ *p, ناپ_t n)
{
	إذا (n == 0)
		أرجع;
	(فراغ)memset_s(p, n, 0, n);
}

#وإلا /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
ساكن فراغ (* متطاير ssh_bzero)(فراغ *, ناپ_t) = bzero;

فراغ
explicit_bzero(فراغ *p, ناپ_t n)
{
	إذا (n == 0)
		أرجع;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#إذا defined(__has_feature)
# إذا __has_feature(حافظہ_sanitizer)
	memset(p, 0, n);
# endif
#جے_انت

	ssh_bzero(p, n);
}

#جے_انت /* HAVE_MEMSET_S */

#جے_انت /* HAVE_EXPLICIT_BZERO */
