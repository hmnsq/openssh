/* Placed in the public domain */

#include "includes.h"

#ifndef HAVE_GETPAGESIZE

#include <unistd.h>
#include <limits.h>

ཧྲིལ
getpagesize(void)
{
#གལ་ཏེ defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	གལ་ཏེ (r > 0 && r < INT_MAX)
		ཕྱིར (ཧྲིལ)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	ཕྱིར 4096;
}

#endif /* HAVE_GETPAGESIZE */
