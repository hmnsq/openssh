/* Placed in the public domain.  */

/*
 * _FORTIFY_SOURCE includes a misguided check for FD_SET(n)/FD_ISSET(b)
 * where n > FD_SETSIZE. This breaks OpenSSH and other programs that
 * explicitly allocate fd_sets. To avoid this, we wrap FD_SET in a
 * function compiled without _FORTIFY_SOURCE.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "config.h"

#ਜੇ defined(HAVE_FEATURES_H) && defined(FORTIFY_ਸਰੋਤ)
# include <features.h>
# ਜੇ defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  ਜੇ __GLIBC_PREREQ(2, 15) && (FORTIFY_ਸਰੋਤ > 0)
#   undef FORTIFY_ਸਰੋਤ
#   undef __USE_FORTIFY_LEVEL
#   include <sys/socket.h>
ਖਾਲੀ kludge_FD_ਸੈੱਟ(ਪੂਰਨ n, fd_set *ਸੈੱਟ) {
	FD_SET(n, ਸੈੱਟ);
}
ਪੂਰਨ kludge_FD_ISSET(ਪੂਰਨ n, fd_set *ਸੈੱਟ) {
	ਵਾਪਸ FD_ISSET(n, ਸੈੱਟ);
}
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#ਜੇ_ਅੰਤ /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

