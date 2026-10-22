/* Placed in the public domain */

#ضمن "includes.h"

#جيڪڏهن_وصف_نه_ٿيل HAVE_GETPAGESIZE

#ضمن <unistd.h>
#ضمن <limits.h>

صحيح
getpagesize(فراغ)
{
#إذا defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	ڊگهو r = sysconf(_SC_PAGESIZE);
	إذا (r > 0 && r < وڌ_کان_وڌ_عدد)
		أرجع (صحيح)r;
#جيڪڏهن_پورو
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	أرجع 4096;
}

#جيڪڏهن_پورو /* HAVE_GETPAGESIZE */
