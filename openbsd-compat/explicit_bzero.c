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

#اگر_غیر_تعریف_شدہ HAVE_EXPLICIT_BZERO

#اگر_تعریف_شدہ HAVE_EXPLICIT_MEMSET

خالی
explicit_bzero(خالی *p, سائز_t n)
{
	(خالی)explicit_memset(p, 0, n);
}

#وگرنہ_اگر defined(HAVE_MEMSET_S)

خالی
explicit_bzero(خالی *p, سائز_t n)
{
	اگر (n == 0)
		واپس;
	(خالی)memset_s(p, n, 0, n);
}

#ورنہ /* HAVE_MEMSET_S */

/*
 * Indirect bzero through a volatile pointer to hopefully avoid
 * dead-store optimisation eliminating the call.
 */
ساکن خالی (* متلون ssh_bzero)(خالی *, سائز_t) = bzero;

خالی
explicit_bzero(خالی *p, سائز_t n)
{
	اگر (n == 0)
		واپس;
	/*
	 * clang -fsanitize=memory needs to intercept memset-like functions
	 * to correctly detect memory initialisation. Make sure one is called
	 * directly since our indirection trick above successfully confuses it.
	 */
#اگر defined(__has_feature)
# اگر __has_feature(حافظہ_sanitizer)
	memset(p, 0, n);
# endif
#اگر_ختم

	ssh_bzero(p, n);
}

#اگر_ختم /* HAVE_MEMSET_S */

#اگر_ختم /* HAVE_EXPLICIT_BZERO */
