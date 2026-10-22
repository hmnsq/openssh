/* Placed in the public domain */

#شامل "includes.h"

#ifndef HAVE_GETPAGESIZE

#شامل <unistd.h>
#شامل <limits.h>

صحیح
getpagesize(تهی)
{
#اگر defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	اگر (r > 0 && r < INT_MAX)
		بازگشت (صحیح)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	بازگشت 4096;
}

#endif /* HAVE_GETPAGESIZE */
