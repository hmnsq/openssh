/* Placed in the public domain.  */

/*
 * _FORTIFY_SOURCE includes a misguided check for FD_SET(n)/FD_ISSET(b)
 * where n > FD_SETSIZE. This breaks OpenSSH and other programs that
 * explicitly allocate fd_sets. To avoid this, we wrap FD_SET in a
 * function compiled without _FORTIFY_SOURCE.
 */

#شامل "config.h"

#اگر defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# اگر defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  اگر __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   undef _FORTIFY_SOURCE
#   undef __USE_FORTIFY_LEVEL
#   include <sys/socket.h>
تهی kludge_FD_SET(صحیح n, fd_set *set) {
	FD_SET(n, set);
}
صحیح kludge_FD_ISSET(صحیح n, fd_set *set) {
	بازگشت FD_ISSET(n, set);
}
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

