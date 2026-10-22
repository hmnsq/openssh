/* Placed in the public domain.  */

/*
 * _FORTIFY_SOURCE includes a misguided check for FD_SET(n)/FD_ISSET(b)
 * where n > FD_SETSIZE. This breaks OpenSSH and other programs that
 * explicitly allocate fd_sets. To avoid this, we wrap FD_SET in a
 * function compiled without _FORTIFY_SOURCE.
 */

#ಅನ್ತರ್ಭಾವ "config.h"

#ಆದರೆ defined(HAVE_FEATURES_H) && defined(FORTIFY_ಮೂಲ)
# include <features.h>
# ಆದರೆ defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  ಆದರೆ __GLIBC_PREREQ(2, 15) && (FORTIFY_ಮೂಲ > 0)
#   undef FORTIFY_ಮೂಲ
#   undef __USE_FORTIFY_LEVEL
#   include <sys/socket.h>
ಶೂನ್ಯ kludge_FD_ಗಣ(ಪೂರ್ಣಾಂಕ n, fd_set *ಗಣ) {
	FD_SET(n, ಗಣ);
}
ಪೂರ್ಣಾಂಕ kludge_FD_ISSET(ಪೂರ್ಣಾಂಕ n, fd_set *ಗಣ) {
	ಹಿಂತಿರುಗಿ FD_ISSET(n, ಗಣ);
}
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

