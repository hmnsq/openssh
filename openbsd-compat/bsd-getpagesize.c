/* Placed in the public domain */

#ضمن "includes.h"

#ifndef HAVE_GETPAGESIZE

#ضمن <unistd.h>
#ضمن <limits.h>

صحيح
getpagesize(فراغ)
{
#ܐܢ defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	ܐܢ (r > 0 && r < INT_MAX)
		ܦܢܐ (صحيح)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	ܦܢܐ 4096;
}

#endif /* HAVE_GETPAGESIZE */
