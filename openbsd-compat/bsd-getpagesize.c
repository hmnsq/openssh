/* Placed in the public domain */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifndef HAVE_GETPAGESIZE

#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

ಪೂರ್ಣಾಙ್ಕ
getpagesize(ಶೂನ್ಯ)
{
#ಯದಿ defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	ಯದಿ (r > 0 && r < INT_MAX)
		ಪ್ರತ್ಯಾಗಮ (ಪೂರ್ಣಾಙ್ಕ)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	ಪ್ರತ್ಯಾಗಮ 4096;
}

#endif /* HAVE_GETPAGESIZE */
