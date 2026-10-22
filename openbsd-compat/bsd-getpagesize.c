/* Placed in the public domain */

#include "includes.h"

#ifndef HAVE_GETPAGESIZE

#include <unistd.h>
#include <limits.h>

ຈຳນວນເຕັມ
getpagesize(void)
{
#ຖ້າ defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	ຖ້າ (r > 0 && r < INT_MAX)
		ສົ່ງຄືນ (ຈຳນວນເຕັມ)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	ສົ່ງຄືນ 4096;
}

#endif /* HAVE_GETPAGESIZE */
