/* Placed in the public domain */

#شامل "includes.h"

#اگر_غیر_تعریف_شدہ HAVE_GETPAGESIZE

#شامل <unistd.h>
#شامل <limits.h>

صحیح
getpagesize(خالی)
{
#اگر defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	طویل r = sysconf(_SC_PAGESIZE);
	اگر (r > 0 && r < زیادہ_سے_زیادہ_عدد)
		واپس (صحیح)r;
#اگر_ختم
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	واپس 4096;
}

#اگر_ختم /* HAVE_GETPAGESIZE */
