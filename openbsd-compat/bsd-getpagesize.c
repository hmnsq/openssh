/* Placed in the public domain */

#ضمن "includes.h"

#جے_بنا_تعریف HAVE_GETPAGESIZE

#ضمن <unistd.h>
#ضمن <limits.h>

صحيح
getpagesize(فراغ)
{
#إذا defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	لما r = sysconf(_SC_PAGESIZE);
	إذا (r > 0 && r < ودھ_توں_ودھ_عدد)
		أرجع (صحيح)r;
#جے_انت
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	أرجع 4096;
}

#جے_انت /* HAVE_GETPAGESIZE */
