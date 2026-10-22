/* Placed in the public domain */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GETPAGESIZE

#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

ಪೂರ್ಣಾಂಕ
getpagesize(ಶೂನ್ಯ)
{
#ಆದರೆ defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
	ದೀರ್ಘ r = sysconf(_SC_PAGESIZE);
	ಆದರೆ (r > 0 && r < ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		ಹಿಂತಿರುಗಿ (ಪೂರ್ಣಾಂಕ)r;
#ಆದರೆ_ಅಂತ್ಯ
	/*
	 * This is at the lower end of common values and appropriate for
	 * our current use of getpagesize() in recallocarray().
	 */
	ಹಿಂತಿರುಗಿ 4096;
}

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_GETPAGESIZE */
