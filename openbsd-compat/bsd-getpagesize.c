/* Placed in the public domain */

#include "includes.h"

#ifndef HAVE_GETPAGESIZE

#include <unistd.h>
#include <limits.h>

정수
getpagesize(void)
{
#만약 defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	만약 (r > 0 && r < INT_MAX)
		반환 (정수)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	반환 4096;
}

#endif /* HAVE_GETPAGESIZE */
