/* Placed in the public domain */

#ضمن "includes.h"

#ifndef HAVE_GETPAGESIZE

#ضمن <unistd.h>
#ضمن <limits.h>

صحيح
getpagesize(فراغ)
{
#𐡄𐡍 defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	𐡄𐡍 (r > 0 && r < INT_MAX)
		أرجع (صحيح)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	أرجع 4096;
}

#endif /* HAVE_GETPAGESIZE */
