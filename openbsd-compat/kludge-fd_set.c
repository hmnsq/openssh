/* Placed in the public domain.  */

/*
 * _FORTIFY_SOURCE includes a misguided check for FD_SET(n)/FD_ISSET(b)
 * where n > FD_SETSIZE. This breaks OpenSSH and other programs that
 * explicitly allocate fd_sets. To avoid this, we wrap FD_SET in a
 * function compiled without _FORTIFY_SOURCE.
 */

#అన్తర్భావ "config.h"

#ఒకవేళ defined(HAVE_FEATURES_H) && defined(FORTIFY_ఆధారం)
# include <features.h>
# ఒకవేళ defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  ఒకవేళ __GLIBC_PREREQ(2, 15) && (FORTIFY_ఆధారం > 0)
#   undef FORTIFY_ఆధారం
#   undef __USE_FORTIFY_LEVEL
#   include <sys/socket.h>
శూన్య kludge_FD_సమితి(పూర్ణాంకం n, fd_set *సమితి) {
	FD_SET(n, సమితి);
}
పూర్ణాంకం kludge_FD_ISSET(పూర్ణాంకం n, fd_set *సమితి) {
	తిరిగి FD_ISSET(n, సమితి);
}
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#అయితే_ముగింపు /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

