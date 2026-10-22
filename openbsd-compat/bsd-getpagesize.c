/* Placed in the public domain */

#અન્તર્ભાવ "includes.h"

#ifndef HAVE_GETPAGESIZE

#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>

પૂર્ણાંક
getpagesize(શૂન્ય)
{
#જો defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	જો (r > 0 && r < INT_MAX)
		પાછા (પૂર્ણાંક)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	પાછા 4096;
}

#endif /* HAVE_GETPAGESIZE */
