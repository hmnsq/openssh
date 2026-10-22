/* Placed in the public domain */

#अन्तर्भाव "includes.h"

#यदि_अपरिभाषितम् HAVE_GETPAGESIZE

#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>

पूर्णाङ्क
getpagesize(शून्य)
{
#यदि defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	दीर्घ r = sysconf(_SC_PAGESIZE);
	यदि (r > 0 && r < अधिकतम_पूर्णाङ्कः)
		प्रत्यागम (पूर्णाङ्क)r;
#यदि_अन्तः
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	प्रत्यागम 4096;
}

#यदि_अन्तः /* HAVE_GETPAGESIZE */
