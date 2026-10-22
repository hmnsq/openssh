/* Placed in the public domain */

#समावेश "includes.h"

#अगर_अघोषित HAVE_GETPAGESIZE

#समावेश <unistd.h>
#समावेश <limits.h>

पूर्णांक
getpagesize(व्योम)
{
#अगर defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	दीर्घ r = sysconf(_SC_PAGESIZE);
	अगर (r > 0 && r < पूर्णांक_उच्च)
		वापस (पूर्णांक)r;
#पूर्ण_अगर
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	वापस 4096;
}

#पूर्ण_अगर /* HAVE_GETPAGESIZE */
