/* Placed in the public domain */

#அந்தர்பாவ "includes.h"

#ifndef HAVE_GETPAGESIZE

#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>

முழு
getpagesize(வெறுமை)
{
#எனில் defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	எனில் (r > 0 && r < INT_MAX)
		திரும்பு (முழு)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	திரும்பு 4096;
}

#endif /* HAVE_GETPAGESIZE */
