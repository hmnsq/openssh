/* Placed in the public domain.  */

/*
 * _FORTIFY_SOURCE includes a misguided check for FD_SET(n)/FD_ISSET(b)
 * where n > FD_SETSIZE. This breaks OpenSSH and other programs that
 * explicitly allocate fd_sets. To avoid this, we wrap FD_SET in a
 * function compiled without _FORTIFY_SOURCE.
 */

#अन्तर्भाव "config.h"

#सचे defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# सचे defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  सचे __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   undef _FORTIFY_SOURCE
#   undef __USE_FORTIFY_LEVEL
#   include <sys/socket.h>
शून्य kludge_FD_SET(पूर्णाङ्क n, fd_set *set) {
	FD_SET(n, set);
}
पूर्णाङ्क kludge_FD_ISSET(पूर्णाङ्क n, fd_set *set) {
	पटिनिवत्त FD_ISSET(n, set);
}
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

