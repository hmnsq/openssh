/* Placed in the public domain */

#include "includes.h"

#ifndef HAVE_GETPAGESIZE

#include <unistd.h>
#include <limits.h>

整数
getpagesize(void)
{
#如果 defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	如果 (r > 0 && r < INT_MAX)
		返回 (整数)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	返回 4096;
}

#endif /* HAVE_GETPAGESIZE */
