/* Placed in the public domain */

#ضمن "includes.h"

#که_نه_تعریف_شوی HAVE_GETPAGESIZE

#ضمن <unistd.h>
#ضمن <limits.h>

صحيح
getpagesize(فراغ)
{
#إذا defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	اوږد r = sysconf(_SC_PAGESIZE);
	إذا (r > 0 && r < لوی_عدد)
		أرجع (صحيح)r;
#د_که_پای
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	أرجع 4096;
}

#د_که_پای /* HAVE_GETPAGESIZE */
