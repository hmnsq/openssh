/* Placed in the public domain */

#include "includes.h"

#ifndef HAVE_GETPAGESIZE

#include <unistd.h>
#include <limits.h>

puur_naa_nka
getpagesize(void)
{
#ᱡᱩᱫᱤ defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	ᱡᱩᱫᱤ (r > 0 && r < INT_MAX)
		ᱨᱩᱣᱟᱹᱲ (puur_naa_nka)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	ᱨᱩᱣᱟᱹᱲ 4096;
}

#endif /* HAVE_GETPAGESIZE */
