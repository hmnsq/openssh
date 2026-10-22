/* Placed in the public domain */

#include "includes.h"

#ifndef HAVE_GETPAGESIZE

#include <unistd.h>
#include <limits.h>

ចំនួនគត់
getpagesize(void)
{
#ប្រសិនបើ defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	ប្រសិនបើ (r > 0 && r < INT_MAX)
		ត្រឡប់ (ចំនួនគត់)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	ត្រឡប់ 4096;
}

#endif /* HAVE_GETPAGESIZE */
