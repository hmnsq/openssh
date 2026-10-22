/* Placed in the public domain */

#include "includes.h"

#ifndef HAVE_GETPAGESIZE

#include <unistd.h>
#include <limits.h>

จำนวนเต็ม
getpagesize(void)
{
#ถ้า defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	ถ้า (r > 0 && r < INT_MAX)
		คืน (จำนวนเต็ม)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	คืน 4096;
}

#endif /* HAVE_GETPAGESIZE */
