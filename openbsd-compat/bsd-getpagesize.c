/* Placed in the public domain */

#include "includes.h"

#ifndef HAVE_GETPAGESIZE

#include <unistd.h>
#include <limits.h>

số_nguyên
getpagesize(void)
{
#nếu defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	nếu (r > 0 && r < INT_MAX)
		trả_về (số_nguyên)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	trả_về 4096;
}

#endif /* HAVE_GETPAGESIZE */
