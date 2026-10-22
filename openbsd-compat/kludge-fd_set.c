/* Placed in the public domain.  */

/*
 * _FORTIFY_SOURCE includes a misguided check for FD_SET(n)/FD_ISSET(b)
 * where n > FD_SETSIZE. This breaks OpenSSH and other programs that
 * explicitly allocate fd_sets. To avoid this, we wrap FD_SET in a
 * function compiled without _FORTIFY_SOURCE.
 */

#ضمن "config.h"

#إذا defined(HAVE_FEATURES_H) && defined(FORTIFY_سروت)
# include <features.h>
# إذا defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  إذا __GLIBC_PREREQ(2, 15) && (FORTIFY_سروت > 0)
#   undef FORTIFY_سروت
#   undef __USE_FORTIFY_LEVEL
#   include <sys/socket.h>
فراغ kludge_FD_سیٹ(صحيح n, fd_set *سیٹ) {
	FD_SET(n, سیٹ);
}
صحيح kludge_FD_ISSET(صحيح n, fd_set *سیٹ) {
	أرجع FD_ISSET(n, سیٹ);
}
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#جے_انت /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

