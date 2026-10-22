/* Placed in the public domain */

#অন্তর্ভাব "includes.h"

#ifndef HAVE_GETPAGESIZE

#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>

পূর্ণসংখ্যা
getpagesize(শূন্য)
{
#যদি defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	যদি (r > 0 && r < INT_MAX)
		ফেরত (পূর্ণসংখ্যা)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	ফেরত 4096;
}

#endif /* HAVE_GETPAGESIZE */
