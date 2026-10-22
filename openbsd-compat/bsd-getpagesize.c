/* Placed in the public domain */

#include "includes.h"

#ifndef HAVE_GETPAGESIZE

#include <unistd.h>
#include <limits.h>

ціле
getpagesize(void)
{
#якщо defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	якщо (r > 0 && r < INT_MAX)
		повернути (ціле)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	повернути 4096;
}

#endif /* HAVE_GETPAGESIZE */
