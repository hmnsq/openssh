/* Placed in the public domain */

#अन्तर्भाव "includes.h"

#ifndef HAVE_GETPAGESIZE

#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>

पूर्णांक
getpagesize(शून्य)
{
#जर defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	दीर्घ r = sysconf(_SC_PAGESIZE);
	जर (r > 0 && r < पूर्णांक_उच्च)
		परत (पूर्णांक)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	परत 4096;
}

#endif /* HAVE_GETPAGESIZE */
