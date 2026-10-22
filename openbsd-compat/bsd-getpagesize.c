/* Placed in the public domain */

#అన్తర్భావ "includes.h"

#నిర్వచితం_కాకపోతే HAVE_GETPAGESIZE

#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>

పూర్ణాంకం
getpagesize(శూన్య)
{
#ఒకవేళ defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	దీర్ఘ r = sysconf(_SC_PAGESIZE);
	ఒకవేళ (r > 0 && r < గరిష్ఠ_పూర్ణాంకం)
		తిరిగి (పూర్ణాంకం)r;
#అయితే_ముగింపు
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	తిరిగి 4096;
}

#అయితే_ముగింపు /* HAVE_GETPAGESIZE */
