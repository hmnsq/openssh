/* Placed in the public domain */

#include "includes.h"

#ifndef HAVE_GETPAGESIZE

#include <unistd.h>
#include <limits.h>

ཧྲིལ
getpagesize(void)
{
#གལ་སྲིད defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	གལ་སྲིད (r > 0 && r < INT_MAX)
		ལོག (ཧྲིལ)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	ལོག 4096;
}

#endif /* HAVE_GETPAGESIZE */
