/* Placed in the public domain */

#ضمن "includes.h"

#اگر_تعریف_نشده HAVE_GETPAGESIZE

#ضمن <unistd.h>
#ضمن <limits.h>

صحيح
getpagesize(فراغ)
{
#إذا defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	دراز r = sysconf(_SC_PAGESIZE);
	إذا (r > 0 && r < بیشترین_صحیح)
		أرجع (صحيح)r;
#پایان_اگر
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	أرجع 4096;
}

#پایان_اگر /* HAVE_GETPAGESIZE */
