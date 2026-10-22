/* Placed in the public domain */

#include "includes.h"

#ifndef HAVE_GETPAGESIZE

#include <unistd.h>
#include <limits.h>

puur_naa_nka
getpagesize(void)
{
#ᨀᨘ defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	ᨀᨘ (r > 0 && r < INT_MAX)
		ᨀᨘᨒ (puur_naa_nka)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	ᨀᨘᨒ 4096;
}

#endif /* HAVE_GETPAGESIZE */
