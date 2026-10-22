/* Placed in the public domain */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETPAGESIZE

#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

ਪੂਰਨ
getpagesize(ਖਾਲੀ)
{
#ਜੇ defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	ਲੰਮਾ r = sysconf(_SC_PAGESIZE);
	ਜੇ (r > 0 && r < ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		ਵਾਪਸ (ਪੂਰਨ)r;
#ਜੇ_ਅੰਤ
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	ਵਾਪਸ 4096;
}

#ਜੇ_ਅੰਤ /* HAVE_GETPAGESIZE */
