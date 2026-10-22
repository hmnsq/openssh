/* Placed in the public domain.  */

/*
 * _FORTIFY_SOURCE includes a misguided check for FD_SET(n)/FD_ISSET(b)
 * where n > FD_SETSIZE. This breaks OpenSSH and other programs that
 * explicitly allocate fd_sets. To avoid this, we wrap FD_SET in a
 * function compiled without _FORTIFY_SOURCE.
 */

#അന്തര്ഭാവ "config.h"

#എങ്കിൽ defined(HAVE_FEATURES_H) && defined(_FORTIFY_SOURCE)
# include <features.h>
# എങ്കിൽ defined(__GNU_LIBRARY__) && defined(__GLIBC_PREREQ)
#  എങ്കിൽ __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0)
#   undef _FORTIFY_SOURCE
#   undef __USE_FORTIFY_LEVEL
#   include <sys/socket.h>
ശൂന്യം kludge_FD_SET(പൂർണ്ണസംഖ്യ n, fd_set *set) {
	FD_SET(n, set);
}
പൂർണ്ണസംഖ്യ kludge_FD_ISSET(പൂർണ്ണസംഖ്യ n, fd_set *set) {
	തിരികെ FD_ISSET(n, set);
}
#  endif /* __GLIBC_PREREQ(2, 15) && (_FORTIFY_SOURCE > 0) */
# endif /* __GNU_LIBRARY__ && __GLIBC_PREREQ */
#endif /* HAVE_FEATURES_H && _FORTIFY_SOURCE */

