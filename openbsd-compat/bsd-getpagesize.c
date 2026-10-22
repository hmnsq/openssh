/* Placed in the public domain */

#অন্তর্ভাৱ "includes.h"

#ifndef HAVE_GETPAGESIZE

#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <limits.h>

পূর্ণাঙ্ক
getpagesize(শূন্য)
{
#যদি defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	যদি (r > 0 && r < INT_MAX)
		ঘূৰাই (পূর্ণাঙ্ক)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	ঘূৰাই 4096;
}

#endif /* HAVE_GETPAGESIZE */
