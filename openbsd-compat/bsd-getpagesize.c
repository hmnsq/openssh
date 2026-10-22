/* Placed in the public domain */

#अन्तर्भाव "includes.h"

#ifndef HAVE_GETPAGESIZE

#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>

पूर्णाङ्क
getpagesize(शून्य)
{
#सचे defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	सचे (r > 0 && r < INT_MAX)
		पटिनिवत्त (पूर्णाङ्क)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	पटिनिवत्त 4096;
}

#endif /* HAVE_GETPAGESIZE */
