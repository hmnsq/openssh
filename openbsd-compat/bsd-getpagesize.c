/* Placed in the public domain */

#include "includes.h"

#ifndef HAVE_GETPAGESIZE

#include <unistd.h>
#include <limits.h>

ကိန်းပြည့်
getpagesize(void)
{
#အကယ်၍ defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	အကယ်၍ (r > 0 && r < INT_MAX)
		ပြန်ပေး (ကိန်းပြည့်)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	ပြန်ပေး 4096;
}

#endif /* HAVE_GETPAGESIZE */
