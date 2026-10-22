/* Placed in the public domain */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifndef HAVE_GETPAGESIZE

#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
getpagesize(ଶୂନ୍ୟ)
{
#ଯଦି defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	ଯଦି (r > 0 && r < INT_MAX)
		ଫେରନ୍ତୁ (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	ଫେରନ୍ତୁ 4096;
}

#endif /* HAVE_GETPAGESIZE */
