/* Placed in the public domain */

#അന്തര്ഭാവ "includes.h"

#ifndef HAVE_GETPAGESIZE

#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>

പൂർണ്ണസംഖ്യ
getpagesize(ശൂന്യം)
{
#എങ്കിൽ defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	long r = sysconf(_SC_PAGESIZE);
	എങ്കിൽ (r > 0 && r < INT_MAX)
		തിരികെ (പൂർണ്ണസംഖ്യ)r;
#endif
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	തിരികെ 4096;
}

#endif /* HAVE_GETPAGESIZE */
