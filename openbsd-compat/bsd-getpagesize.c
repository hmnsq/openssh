/* Placed in the public domain */

#include "includes.h"

#ifndef HAVE_GETPAGESIZE

#include <unistd.h>
#include <limits.h>

පූර්ණ_සංඛ්‍යා
getpagesize(void)
{
#නම් defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	නම් (r > 0 && r < INT_MAX)
		ආපසු (පූර්ණ_සංඛ්‍යා)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	ආපසු 4096;
}

#endif /* HAVE_GETPAGESIZE */
