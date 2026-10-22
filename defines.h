/*
 * Copyright (c) 1999-2003 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _DEFINES_H
#define _DEFINES_H

/* Constants */

#जर defined(HAVE_DECL_SHUT_RD) && HAVE_DECL_SHUT_RD == 0
गणना
{
  SHUT_RD = 0,		/* No more receptions.  */
  SHUT_WR,			/* No more transmissions.  */
  SHUT_RDWR			/* No more receptions or transmissions.  */
};
# define SHUT_RD   SHUT_RD
# define SHUT_WR   SHUT_WR
# define SHUT_RDWR SHUT_RDWR
#endif

/*
 * Cygwin doesn't really have a notion of reserved ports.  It is still
 * is useful on the client side so for compatibility it defines as 1024 via
 * netinet/in.h inside an enum.  We * don't actually want that restriction
 * so we want to set that to zero, but we can't do it direct in config.h
 * because it'll cause a conflicting definition the first time we include
 * netinet/in.h.
 */

#ifdef HAVE_CYGWIN
#define IPPORT_RESERVED 0
#endif

/*
 * Definitions for IP type of service (ip_tos)
 */
#अन्तर्भाव <netinet/ip.h>
#ifndef IPTOS_LOWDELAY
# define IPTOS_LOWDELAY          0x10
# define IPTOS_THROUGHPUT        0x08
# define IPTOS_RELIABILITY       0x04
# define IPTOS_LOWCOST           0x02
# define IPTOS_MINCOST           IPTOS_LOWCOST
#endif /* IPTOS_LOWDELAY */

/*
 * Definitions for DiffServ Codepoints as per RFCs 2474, 3246, 4594 & 8622.
 * These are the 6 most significant bits as they appear on the wire, so the
 * two least significant bits must be zero.
 */
#ifndef IPTOS_DSCP_AF11
# define	IPTOS_DSCP_AF11		0x28
# define	IPTOS_DSCP_AF12		0x30
# define	IPTOS_DSCP_AF13		0x38
# define	IPTOS_DSCP_AF21		0x48
# define	IPTOS_DSCP_AF22		0x50
# define	IPTOS_DSCP_AF23		0x58
# define	IPTOS_DSCP_AF31		0x68
# define	IPTOS_DSCP_AF32		0x70
# define	IPTOS_DSCP_AF33		0x78
# define	IPTOS_DSCP_AF41		0x88
# define	IPTOS_DSCP_AF42		0x90
# define	IPTOS_DSCP_AF43		0x98
# define	IPTOS_DSCP_EF		0xb8
#endif /* IPTOS_DSCP_AF11 */
#ifndef IPTOS_DSCP_CS0
# define	IPTOS_DSCP_CS0		0x00
# define	IPTOS_DSCP_CS1		0x20
# define	IPTOS_DSCP_CS2		0x40
# define	IPTOS_DSCP_CS3		0x60
# define	IPTOS_DSCP_CS4		0x80
# define	IPTOS_DSCP_CS5		0xa0
# define	IPTOS_DSCP_CS6		0xc0
# define	IPTOS_DSCP_CS7		0xe0
#endif /* IPTOS_DSCP_CS0 */
#ifndef IPTOS_DSCP_VA
# define	IPTOS_DSCP_VA		0xb0
#endif /* IPTOS_DSCP_VA */
#ifndef IPTOS_DSCP_EF
# define	IPTOS_DSCP_EF		0xb8
#endif /* IPTOS_DSCP_EF */
#ifndef IPTOS_DSCP_LE
# define	IPTOS_DSCP_LE		0x04
#endif /* IPTOS_DSCP_LE */
#ifndef IPTOS_PREC_CRITIC_ECP
# define IPTOS_PREC_CRITIC_ECP		0xa0
#endif
#ifndef IPTOS_PREC_INTERNETCONTROL
# define IPTOS_PREC_INTERNETCONTROL	0xc0
#endif
#ifndef IPTOS_PREC_NETCONTROL
# define IPTOS_PREC_NETCONTROL		0xe0
#endif

#ifndef PATH_MAX
# ifdef _POSIX_PATH_MAX
# define PATH_MAX _POSIX_PATH_MAX
# endif
#endif

#ifndef MAXPATHLEN
# ifdef PATH_MAX
#  define MAXPATHLEN PATH_MAX
# अन्यथा /* PATH_MAX */
#  define MAXPATHLEN 64
# endif /* PATH_MAX */
#endif /* MAXPATHLEN */

#ifndef HOST_NAME_MAX
# include "netdb.h" /* for MAXHOSTNAMELEN */
# जर defined(_POSIX_HOST_NAME_MAX)
#  define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# elif defined(MAXHOSTNAMELEN)
#  define HOST_NAME_MAX MAXHOSTNAMELEN
# अन्यथा
#  define HOST_NAME_MAX	255
# endif
#endif /* HOST_NAME_MAX */

#जर defined(HAVE_DECL_MAXSYMLINKS) && HAVE_DECL_MAXSYMLINKS == 0
# define MAXSYMLINKS 5
#endif

#ifndef STDIN_FILENO
# define STDIN_FILENO    0
#endif
#ifndef STDOUT_FILENO
# define STDOUT_FILENO   1
#endif
#ifndef STDERR_FILENO
# define STDERR_FILENO   2
#endif

#ifndef NGROUPS_MAX	/* Disable groupaccess if NGROUP_MAX is not set */
#ifdef NGROUPS
#define NGROUPS_MAX NGROUPS
#अन्यथा
#define NGROUPS_MAX 0
#endif
#endif

#जर defined(HAVE_DECL_O_NONBLOCK) && HAVE_DECL_O_NONBLOCK == 0
# define O_NONBLOCK      00004	/* Non Blocking Open */
#endif

#ifndef S_IFSOCK
# define S_IFSOCK 0
#endif /* S_IFSOCK */

#ifndef S_ISDIR
# define S_ISDIR(mode)	(((mode) & (_S_IFMT)) == (_S_IFDIR))
#endif /* S_ISDIR */

#ifndef S_ISREG
# define S_ISREG(mode)	(((mode) & (_S_IFMT)) == (_S_IFREG))
#endif /* S_ISREG */

#ifndef S_ISLNK
# define S_ISLNK(mode)	(((mode) & S_IFMT) == S_IFLNK)
#endif /* S_ISLNK */

#ifndef S_IXUSR
# define S_IXUSR			0000100	/* execute/search permission, */
# define S_IXGRP			0000010	/* execute/search permission, */
# define S_IXOTH			0000001	/* execute/search permission, */
# define _S_IWUSR			0000200	/* write permission, */
# define S_IWUSR			_S_IWUSR	/* write permission, owner */
# define S_IWGRP			0000020	/* write permission, group */
# define S_IWOTH			0000002	/* write permission, other */
# define S_IRUSR			0000400	/* read permission, owner */
# define S_IRGRP			0000040	/* read permission, group */
# define S_IROTH			0000004	/* read permission, other */
# define S_IRWXU			0000700	/* read, write, execute */
# define S_IRWXG			0000070	/* read, write, execute */
# define S_IRWXO			0000007	/* read, write, execute */
#endif /* S_IXUSR */

#जर !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
#define MAP_ANON MAP_ANONYMOUS
#endif

#ifndef MAP_FAILED
# define MAP_FAILED ((शून्य *)-1)
#endif

/*
SCO Open Server 3 has INADDR_LOOPBACK defined in rpc/rpc.h but
including rpc/rpc.h breaks Solaris 6
*/
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK ((u_long)0x7f000001)
#endif

/* Types */

/* If sys/types.h does not supply intXX_t, supply them ourselves */
/* (or die trying) */

#ifndef HAVE_U_INT
प्रकारव्याख्या अचिन्हित लघु u_short;
प्रकारव्याख्या अचिन्हित पूर्णांक u_int;
प्रकारव्याख्या अचिन्हित दीर्घ u_long;
#endif

#ifndef HAVE_INTXX_T
प्रकारव्याख्या चिन्हित अक्षर int8_t;
# जर (SIZEOF_SHORT_INT == 2)
प्रकारव्याख्या लघु पूर्णांक int16_t;
# अन्यथा
#   error "16 bit int type not found."
# endif
# जर (SIZEOF_INT == 4)
प्रकारव्याख्या पूर्णांक int32_t;
# अन्यथा
#   error "32 bit int type not found."
# endif
#endif

/* If sys/types.h does not supply u_intXX_t, supply them ourselves */
#ifndef HAVE_U_INTXX_T
# ifdef HAVE_UINTXX_T
प्रकारव्याख्या uint8_t u_int8_t;
प्रकारव्याख्या uint16_t u_int16_t;
प्रकारव्याख्या uint32_t u_int32_t;
# define HAVE_U_INTXX_T 1
# अन्यथा
प्रकारव्याख्या अचिन्हित अक्षर u_int8_t;
#  जर (SIZEOF_SHORT_INT == 2)
प्रकारव्याख्या अचिन्हित लघु पूर्णांक u_int16_t;
#  अन्यथा
#    error "16 bit int type not found."
#  endif
#  जर (SIZEOF_INT == 4)
प्रकारव्याख्या अचिन्हित पूर्णांक u_int32_t;
#  अन्यथा
#    error "32 bit int type not found."
#  endif
# endif
#define __BIT_TYPES_DEFINED__
#endif

#जर !defined(LLONG_MIN) && defined(LONG_LONG_MIN)
#define LLONG_MIN LONG_LONG_MIN
#endif
#जर !defined(LLONG_MAX) && defined(LONG_LONG_MAX)
#define LLONG_MAX LONG_LONG_MAX
#endif

#ifndef UINT32_MAX
# जर defined(HAVE_DECL_UINT32_MAX) && (HAVE_DECL_UINT32_MAX == 0)
#  जर (SIZEOF_INT == 4)
#    define UINT32_MAX	अच_पूर्णांक_उच्च
#  endif
# endif
#endif

/* 64-bit types */
#ifndef HAVE_INT64_T
# जर (SIZEOF_LONG_INT == 8)
प्रकारव्याख्या दीर्घ पूर्णांक int64_t;
# अन्यथा
#  जर (SIZEOF_LONG_LONG_INT == 8)
प्रकारव्याख्या दीर्घ दीर्घ पूर्णांक int64_t;
#  endif
# endif
#endif
#ifndef HAVE_U_INT64_T
# जर (SIZEOF_LONG_INT == 8)
प्रकारव्याख्या अचिन्हित दीर्घ पूर्णांक u_int64_t;
# अन्यथा
#  जर (SIZEOF_LONG_LONG_INT == 8)
प्रकारव्याख्या अचिन्हित दीर्घ दीर्घ पूर्णांक u_int64_t;
#  endif
# endif
#endif

#ifndef HAVE_UINTXX_T
प्रकारव्याख्या u_int8_t uint8_t;
प्रकारव्याख्या u_int16_t uint16_t;
प्रकारव्याख्या u_int32_t uint32_t;
प्रकारव्याख्या u_int64_t uint64_t;
#endif

#ifndef HAVE_INTMAX_T
प्रकारव्याख्या दीर्घ दीर्घ intmax_t;
#endif

#ifndef HAVE_UINTMAX_T
प्रकारव्याख्या अचिन्हित दीर्घ दीर्घ uintmax_t;
#endif

#जर SIZEOF_TIME_T == SIZEOF_LONG_LONG_INT
# define SSH_TIME_T_MAX LLONG_MAX
#अन्यथा
# define SSH_TIME_T_MAX पूर्णांक_उच्च
#endif

#ifndef HAVE_U_CHAR
प्रकारव्याख्या अचिन्हित अक्षर u_char;
# define HAVE_U_CHAR
#endif /* HAVE_U_CHAR */

#ifndef ULLONG_MAX
# define ULLONG_MAX ((अचिन्हित दीर्घ दीर्घ)-1)
#endif

#ifndef SIZE_T_MAX
#define SIZE_T_MAX अच_दीर्घ_उच्च
#endif /* SIZE_T_MAX */

#ifndef HAVE_SIZE_T
प्रकारव्याख्या अचिन्हित पूर्णांक माप_प्रकार;
# define HAVE_SIZE_T
# define SIZE_T_MAX अच_पूर्णांक_उच्च
#endif /* HAVE_SIZE_T */

#ifndef SIZE_MAX
#define SIZE_MAX SIZE_T_MAX
#endif

#ifndef INT32_MAX
# जर (SIZEOF_INT == 4)
#  define INT32_MAX पूर्णांक_उच्च
# elif (SIZEOF_LONG == 4)
#  define INT32_MAX दीर्घ_उच्च
# अन्यथा
#  error "need INT32_MAX"
# endif
#endif

#ifndef INT64_MAX
# जर (SIZEOF_INT == 8)
#  define INT64_MAX पूर्णांक_उच्च
# elif (SIZEOF_LONG == 8)
#  define INT64_MAX दीर्घ_उच्च
# elif (SIZEOF_LONG_LONG_INT == 8)
#  define INT64_MAX LLONG_MAX
# अन्यथा
#  error "need INT64_MAX"
# endif
#endif

#ifndef HAVE_SSIZE_T
प्रकारव्याख्या पूर्णांक ssize_t;
#define SSIZE_MAX पूर्णांक_उच्च
# define HAVE_SSIZE_T
#endif /* HAVE_SSIZE_T */

#ifndef HAVE_CLOCK_T
प्रकारव्याख्या दीर्घ घड़ी_प्रकार;
# define HAVE_CLOCK_T
#endif /* HAVE_CLOCK_T */

#ifndef HAVE_SA_FAMILY_T
प्रकारव्याख्या पूर्णांक sa_family_t;
# define HAVE_SA_FAMILY_T
#endif /* HAVE_SA_FAMILY_T */

#ifndef HAVE_PID_T
प्रकारव्याख्या पूर्णांक pid_t;
# define HAVE_PID_T
#endif /* HAVE_PID_T */

#ifndef HAVE_SIG_ATOMIC_T
प्रकारव्याख्या पूर्णांक संक_पूर्ण_प्रकार;
# define HAVE_SIG_ATOMIC_T
#endif /* HAVE_SIG_ATOMIC_T */

#ifndef HAVE_MODE_T
प्रकारव्याख्या पूर्णांक mode_t;
# define HAVE_MODE_T
#endif /* HAVE_MODE_T */

#जर !defined(HAVE_SS_FAMILY_IN_SS) && defined(HAVE___SS_FAMILY_IN_SS)
# define ss_family __ss_family
#endif /* !defined(HAVE_SS_FAMILY_IN_SS) && defined(HAVE_SA_FAMILY_IN_SS) */

#ifndef HAVE_SYS_UN_H
संरचना	sockaddr_un {
	लघु	sun_family;		/* AF_UNIX */
	अक्षर	sun_path[108];		/* path name (gag) */
};
#endif /* HAVE_SYS_UN_H */

#ifndef HAVE_IN_ADDR_T
प्रकारव्याख्या u_int32_t	in_addr_t;
#endif
#ifndef HAVE_IN_PORT_T
प्रकारव्याख्या u_int16_t	in_port_t;
#endif

#जर defined(BROKEN_SYS_TERMIO_H) && !defined(_STRUCT_WINSIZE)
#define _STRUCT_WINSIZE
संरचना winsize {
      अचिन्हित लघु ws_row;          /* rows, in characters */
      अचिन्हित लघु ws_col;          /* columns, in character */
      अचिन्हित लघु ws_xpixel;       /* horizontal size, pixels */
      अचिन्हित लघु ws_ypixel;       /* vertical size, pixels */
};
#endif

/* bits needed for select that may not be in the system headers */
#ifndef HAVE_FD_MASK
 प्रकारव्याख्या अचिन्हित दीर्घ पूर्णांक	fd_mask;
#endif

#जर defined(HAVE_DECL_NFDBITS) && HAVE_DECL_NFDBITS == 0
# define	NFDBITS (8 * आकार(अचिन्हित दीर्घ))
#endif

#जर defined(HAVE_DECL_HOWMANY) && HAVE_DECL_HOWMANY == 0
# define howmany(x,y)	(((x)+((y)-1))/(y))
#endif

/* Paths */

#ifndef _PATH_BSHELL
# define _PATH_BSHELL "/bin/sh"
#endif

#ifdef USER_PATH
# ifdef _PATH_STDPATH
#  undef _PATH_STDPATH
# endif
# define _PATH_STDPATH USER_PATH
#endif

#ifndef _PATH_STDPATH
# define _PATH_STDPATH "/usr/bin:/bin:/usr/sbin:/sbin"
#endif

#ifndef SUPERUSER_PATH
# define SUPERUSER_PATH	_PATH_STDPATH
#endif

#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL "/dev/null"
#endif

/* user may have set a different path */
#जर defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY)
# undef _PATH_MAILDIR
#endif /* defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY) */

#ifdef MAIL_DIRECTORY
# define _PATH_MAILDIR MAIL_DIRECTORY
#endif

#ifndef _PATH_NOLOGIN
# define _PATH_NOLOGIN "/etc/nologin"
#endif

/* Define this to be the path of the xauth program. */
#ifdef XAUTH_PATH
#define _PATH_XAUTH XAUTH_PATH
#endif /* XAUTH_PATH */

/* derived from XF4/xc/lib/dps/Xlibnet.h */
#ifndef X_UNIX_PATH
#  ifdef __hpux
#    define X_UNIX_PATH "/var/spool/sockets/X11/%u"
#  अन्यथा
#    define X_UNIX_PATH "/tmp/.X11-unix/X%u"
#  endif
#endif /* X_UNIX_PATH */
#define _PATH_UNIX_X X_UNIX_PATH

#ifndef _PATH_TTY
# define _PATH_TTY "/dev/tty"
#endif

/* Macros */

#जर defined(HAVE_LOGIN_GETCAPBOOL) && defined(HAVE_LOGIN_CAP_H)
# define HAVE_LOGIN_CAP
#endif

#ifndef MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
# define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef roundup
# define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#endif

#ifndef timersub
#define timersub(a, b, result)					\
   करा {								\
      (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
      (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;		\
      जर ((result)->tv_usec < 0) {				\
	 --(result)->tv_sec;					\
	 (result)->tv_usec += 1000000;				\
      }								\
   } पर्यंत (0)
#endif

#ifndef timespeccmp
#define	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#endif

#ifndef TIMEVAL_TO_TIMESPEC
#define	TIMEVAL_TO_TIMESPEC(tv, ts) {					\
	(ts)->tv_sec = (tv)->tv_sec;					\
	(ts)->tv_nsec = (tv)->tv_usec * 1000;				\
}
#endif

#ifndef TIMESPEC_TO_TIMEVAL
#define	TIMESPEC_TO_TIMEVAL(tv, ts) {					\
	(tv)->tv_sec = (ts)->tv_sec;					\
	(tv)->tv_usec = (ts)->tv_nsec / 1000;				\
}
#endif

#ifndef timespeccmp
#define timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#endif

/* Operations on timespecs. */
#ifndef timespecclear
#define	timespecclear(tsp)		(tsp)->tv_sec = (tsp)->tv_nsec = 0
#endif
#ifndef timespeccmp
#define	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#endif
#ifndef timespecadd
#define	timespecadd(tsp, usp, vsp)					\
	करा {								\
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;	\
		जर ((vsp)->tv_nsec >= 1000000000L) {			\
			(vsp)->tv_sec++;				\
			(vsp)->tv_nsec -= 1000000000L;			\
		}							\
	} पर्यंत (0)
#endif
#ifndef timespecsub
#define	timespecsub(tsp, usp, vsp)					\
	करा {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		जर ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} पर्यंत (0)
#endif

#ifndef __P
# define __P(x) x
#endif

#जर !defined(IN6_IS_ADDR_V4MAPPED)
# define IN6_IS_ADDR_V4MAPPED(a) \
	((((u_int32_t *) (a))[0] == 0) && (((u_int32_t *) (a))[1] == 0) && \
	 (((u_int32_t *) (a))[2] == htonl (0xffff)))
#endif /* !defined(IN6_IS_ADDR_V4MAPPED) */

#जर !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#endif /* !defined(__GNUC__) || (__GNUC__ < 2) */

#जर !defined(HAVE_ATTRIBUTE__SENTINEL__) && !defined(__sentinel__)
# define __sentinel__
#endif

#जर !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__bounded__)
# define __bounded__(x, y, z)
#endif

#जर !defined(HAVE_ATTRIBUTE__NONNULL__) && !defined(__nonnull__)
# define __nonnull__(x)
#endif

#जर !defined(HAVE_ATTRIBUTE__NONSTRING__) && !defined(__nonstring__)
# define __nonstring__
#endif

#ifndef OSSH_ALIGNBYTES
#define OSSH_ALIGNBYTES	(आकार(पूर्णांक) - 1)
#endif
#ifndef __CMSG_ALIGN
#define	__CMSG_ALIGN(p) (((u_int)(p) + OSSH_ALIGNBYTES) &~ OSSH_ALIGNBYTES)
#endif

/* Length of the contents of a control message of length len */
#ifndef CMSG_LEN
#define	CMSG_LEN(len)	(__CMSG_ALIGN(आकार(संरचना cmsghdr)) + (len))
#endif

/* Length of the space taken up by a padded control message of length len */
#ifndef CMSG_SPACE
#define	CMSG_SPACE(len)	(__CMSG_ALIGN(आकार(संरचना cmsghdr)) + __CMSG_ALIGN(len))
#endif

/* given pointer to struct cmsghdr, return pointer to data */
#ifndef CMSG_DATA
#define CMSG_DATA(cmsg) ((u_char *)(cmsg) + __CMSG_ALIGN(आकार(संरचना cmsghdr)))
#endif /* CMSG_DATA */

/*
 * RFC 2292 requires to check msg_controllen, in case that the kernel returns
 * an empty list for some reasons.
 */
#ifndef CMSG_FIRSTHDR
#define CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= आकार(संरचना cmsghdr) ? \
	 (संरचना cmsghdr *)(mhdr)->msg_control : \
	 (संरचना cmsghdr *)रिक्त)
#endif /* CMSG_FIRSTHDR */

#जर defined(HAVE_DECL_OFFSETOF) && HAVE_DECL_OFFSETOF == 0
# define दुरत्व(type, member) ((माप_प्रकार) &((type *)0)->member)
#endif

/* Set up BSD-style BYTE_ORDER definition if it isn't there already */
/* XXX: doesn't try to cope with strange byte orders (PDP_ENDIAN) */
#ifndef BYTE_ORDER
# ifndef LITTLE_ENDIAN
#  define LITTLE_ENDIAN  1234
# endif /* LITTLE_ENDIAN */
# ifndef BIG_ENDIAN
#  define BIG_ENDIAN     4321
# endif /* BIG_ENDIAN */
# ifdef शब्द_BIGENDIAN
#  define BYTE_ORDER BIG_ENDIAN
# अन्यथा /* WORDS_BIGENDIAN */
#  define BYTE_ORDER LITTLE_ENDIAN
# endif /* WORDS_BIGENDIAN */
#endif /* BYTE_ORDER */

#जर (defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0) || \
    (defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0) || \
    (defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0) || \
    (defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0)
# define openssh_swap32(v)					\
	(uint32_t)(((uint32_t)(v) & 0xff) << 24 |		\
	((uint32_t)(v) & 0xff00) << 8 |				\
	((uint32_t)(v) & 0xff0000) >> 8 |			\
	((uint32_t)(v) & 0xff000000) >> 24)
# define openssh_swap64(v)					\
	(uint64_t)((((uint64_t)(v) & 0xff) << 56) |		\
	((uint64_t)(v) & 0xff00ULL) << 40 |			\
	((uint64_t)(v) & 0xff0000ULL) << 24 |			\
	((uint64_t)(v) & 0xff000000ULL) << 8 |		\
	((uint64_t)(v) & 0xff00000000ULL) >> 8 |		\
	((uint64_t)(v) & 0xff0000000000ULL) >> 24 |		\
	((uint64_t)(v) & 0xff000000000000ULL) >> 40 |		\
	((uint64_t)(v) & 0xff00000000000000ULL) >> 56)
# ifdef शब्द_BIGENDIAN
#  जर defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) (openssh_swap32(v))
#  endif
#  जर defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#   define le64toh(v) (openssh_swap64(v))
#  endif
#  जर defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) (openssh_swap64(v))
#  endif
#  जर defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) ((uint32_t)v)
#  endif
# अन्यथा
#  जर defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) ((uint32_t)v)
#  endif
#  जर defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#    define le64toh(v) ((uint64_t)v)
#  endif
#  जर defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) ((uint64_t)v)
#  endif
#  जर defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) (openssh_swap32(v))
#  endif
# endif
#endif

/* Function replacement / compatibility hacks */

#जर !defined(HAVE_GETADDRINFO) && (defined(HAVE_OGETADDRINFO) || defined(HAVE_NGETADDRINFO))
# define HAVE_GETADDRINFO
#endif

#ifndef HAVE_GETOPT_OPTRESET
# undef getopt
# undef opterr
# undef optind
# undef optopt
# undef optreset
# undef optarg
# define getopt(ac, av, o)  BSDgetopt(ac, av, o)
# define opterr             BSDopterr
# define optind             BSDoptind
# define optopt             BSDoptopt
# define optreset           BSDoptreset
# define optarg             BSDoptarg
#endif

#जर defined(BROKEN_GETADDRINFO) && defined(HAVE_GETADDRINFO)
# undef HAVE_GETADDRINFO
#endif
#जर defined(BROKEN_GETADDRINFO) && defined(HAVE_FREEADDRINFO)
# undef HAVE_FREEADDRINFO
#endif
#जर defined(BROKEN_GETADDRINFO) && defined(HAVE_GAI_STRERROR)
# undef HAVE_GAI_STRERROR
#endif

#जर defined(HAVE_GETADDRINFO)
# जर defined(HAVE_DECL_AI_NUMERICSERV) && HAVE_DECL_AI_NUMERICSERV == 0
#   define AI_NUMERICSERV	0
# endif
#endif

#जर defined(BROKEN_UPDWTMPX) && defined(HAVE_UPDWTMPX)
# undef HAVE_UPDWTMPX
#endif

#जर defined(BROKEN_SHADOW_EXPIRE) && defined(HAS_SHADOW_EXPIRE)
# undef HAS_SHADOW_EXPIRE
#endif

#जर defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT) && \
    defined(SYSLOG_R_SAFE_IN_SIGHAND)
# define DO_LOG_SAFE_IN_SIGHAND
#endif

#जर !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY)
# define स_हटाओ(s1, s2, n) bcopy((s2), (s1), (n))
#endif /* !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY) */

#ifndef GETPGRP_VOID
# include <unistd.h>
# define getpgrp() getpgrp(0)
#endif

#ifdef USE_BSM_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#endif

#ifdef USE_LINUX_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#endif

#जर !defined(HAVE___func__) && defined(HAVE___FUNCTION__)
#  define __func__ __FUNCTION__
#किंवाजर !defined(HAVE___func__)
#  define __func__ ""
#endif

#जर defined(KRB5) && !defined(HEIMDAL)
#  define krb5_get_err_text(context,code) error_message(code)
#endif

/* Maximum number of file descriptors available */
#ifdef HAVE_SYSCONF
# define SSH_SYSFDMAX sysconf(_SC_OPEN_MAX)
#अन्यथा
# define SSH_SYSFDMAX 10000
#endif

#ifdef FSID_HAS_VAL
/* encode f_fsid into a 64 bit value  */
#define FSID_TO_ULONG(f) \
	((((u_int64_t)(f).val[0] & 0xffffffffUL) << 32) | \
	    ((f).val[1] & 0xffffffffUL))
#किंवाजर defined(FSID_HAS___VAL)
#define FSID_TO_ULONG(f) \
	((((u_int64_t)(f).__val[0] & 0xffffffffUL) << 32) | \
	    ((f).__val[1] & 0xffffffffUL))
#अन्यथा
# define FSID_TO_ULONG(f) ((f))
#endif

#जर defined(__Lynx__)
 /*
  * LynxOS defines these in param.h which we do not want to include since
  * it will also pull in a bunch of kernel definitions.
  */
# define ALIGNBYTES (आकार(पूर्णांक) - 1)
# define ALIGN(p) (((अचिन्हित)p + ALIGNBYTES) & ~ALIGNBYTES)
  /* Missing prototypes on LynxOS */
  पूर्णांक snprintf (अक्षर *, माप_प्रकार, स्थिरांक अक्षर *, ...);
  पूर्णांक mkstemp (अक्षर *);
  अक्षर *crypt (स्थिरांक अक्षर *, स्थिरांक अक्षर *);
  पूर्णांक seteuid (uid_t);
  पूर्णांक setegid (gid_t);
  अक्षर *mkdtemp (अक्षर *);
  पूर्णांक rresvport_af (पूर्णांक *, sa_family_t);
  पूर्णांक innetgr (स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *);
#endif

/*
 * Define this to use pipes instead of socketpairs for communicating with the
 * client program.  Socketpairs do not seem to work on all systems.
 *
 * configure.ac sets this for a few OS's which are known to have problems
 * but you may need to set it yourself
 */
/* #define USE_PIPES 1 */

/**
 ** login recorder definitions
 **/

/* FIXME: put default paths back in */
#ifndef UTMP_FILE
#  ifdef _PATH_UTMP
#    define UTMP_FILE _PATH_UTMP
#  अन्यथा
#    ifdef CONF_UTMP_FILE
#      define UTMP_FILE CONF_UTMP_FILE
#    endif
#  endif
#endif
#ifndef WTMP_FILE
#  ifdef _PATH_WTMP
#    define WTMP_FILE _PATH_WTMP
#  अन्यथा
#    ifdef CONF_WTMP_FILE
#      define WTMP_FILE CONF_WTMP_FILE
#    endif
#  endif
#endif
/* pick up the user's location for lastlog if given */
#ifndef LASTLOG_FILE
#  ifdef _PATH_LASTLOG
#    define LASTLOG_FILE _PATH_LASTLOG
#  अन्यथा
#    ifdef CONF_LASTLOG_FILE
#      define LASTLOG_FILE CONF_LASTLOG_FILE
#    endif
#  endif
#endif

#जर defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
# define USE_SHADOW
#endif

/* The login() library function in libutil is first choice */
#जर defined(HAVE_LOGIN) && !defined(DISABLE_LOGIN)
#  define USE_LOGIN

#अन्यथा
/* Simply select your favourite login types. */
/* Can't do if-else because some systems use several... <sigh> */
#  जर !defined(DISABLE_UTMPX)
#    define USE_UTMPX
#  endif
#  जर defined(UTMP_FILE) && !defined(DISABLE_UTMP)
#    define USE_UTMP
#  endif
#  जर defined(WTMPX_FILE) && !defined(DISABLE_WTMPX)
#    define USE_WTMPX
#  endif
#  जर defined(WTMP_FILE) && !defined(DISABLE_WTMP)
#    define USE_WTMP
#  endif

#endif

#ifndef UT_LINESIZE
# define UT_LINESIZE 8
#endif

/* I hope that the presence of LASTLOG_FILE is enough to detect this */
#जर defined(LASTLOG_FILE) && !defined(DISABLE_LASTLOG)
#  define USE_LASTLOG
#endif

#ifdef HAVE_OSF_SIA
# ifdef USE_SHADOW
#  undef USE_SHADOW
# endif
# define CUSTOM_SYS_AUTH_PASSWD 1
#endif

#जर defined(HAVE_LIBIAF) && defined(HAVE_SET_ID) && !defined(HAVE_SECUREWARE)
# define CUSTOM_SYS_AUTH_PASSWD 1
#endif
#जर defined(HAVE_LIBIAF) && defined(HAVE_SET_ID) && !defined(BROKEN_LIBIAF)
# define USE_LIBIAF
#endif

/* HP-UX 11.11 */
#ifdef BTMP_FILE
# define _PATH_BTMP BTMP_FILE
#endif

#जर defined(USE_BTMP) && defined(_PATH_BTMP)
# define CUSTOM_FAILED_LOGIN
#endif

/** end of login recorder definitions */

#ifdef BROKEN_GETGROUPS
# define getgroups(a,b) ((a)==0 && (b)==रिक्त ? NGROUPS_MAX : getgroups((a),(b)))
#endif

#ifndef IOV_MAX
# जर defined(_XOPEN_IOV_MAX)
#  define	IOV_MAX		_XOPEN_IOV_MAX
# elif defined(DEF_IOV_MAX)
#  define	IOV_MAX		DEF_IOV_MAX
# अन्यथा
#  define	IOV_MAX		16
# endif
#endif

#ifndef EWOULDBLOCK
# define EWOULDBLOCK EAGAIN
#endif

#ifndef INET6_ADDRSTRLEN	/* for non IPv6 machines */
#define INET6_ADDRSTRLEN 46
#endif

#ifndef SSH_IOBUFSZ
# define SSH_IOBUFSZ 8192
#endif

/*
 * We want functions in openbsd-compat, if enabled, to override system ones.
 * We no-op out the weak symbol definition rather than remove it to reduce
 * future sync problems.  Some compilers (eg Unixware) do not allow an
 * empty statement, so we use a bogus function declaration.
 */
#define DEF_WEAK(x)	शून्य __ssh_compat_weak_##x(शून्य)

/*
 * Platforms that have arc4random_uniform() and not arc4random_stir()
 * shouldn't need the latter.
 */
#जर defined(HAVE_ARC4RANDOM) && defined(HAVE_ARC4RANDOM_UNIFORM) && \
    !defined(HAVE_ARC4RANDOM_STIR)
# define arc4random_stir()
#endif

#ifndef HAVE_VA_COPY
# ifdef HAVE___VA_COPY
#  define va_copy(dest, src) __va_copy(dest, src)
# अन्यथा
#  define va_copy(dest, src) (dest) = (src)
# endif
#endif

#ifndef __predict_true
# जर defined(__GNUC__) && \
     ((__GNUC__ > (2)) || (__GNUC__ == (2) && __GNUC_MINOR__ >= (96)))
#  define __predict_true(exp)     __builtin_expect(((exp) != 0), 1)
#  define __predict_false(exp)    __builtin_expect(((exp) != 0), 0)
# अन्यथा
#  define __predict_true(exp)     ((exp) != 0)
#  define __predict_false(exp)    ((exp) != 0)
# endif /* gcc version */
#endif /* __predict_true */

/*
 * sntrup761 uses variable length arrays and c99-style declarations after code,
 * so only enable if the compiler supports them.
 */
#जर defined(VARIABLE_LENGTH_ARRAYS) && defined(VARIABLE_DECLARATION_AFTER_CODE)
# define USE_SNTRUP761X25519	1
/* The ML-KEM768 and ML-DSA implementations also uses C89 features */
# define USE_MLKEM768X25519	1
# define USE_MLDSA		1
#endif

#जर defined(HAVE_DECL_INFINITY) && HAVE_DECL_INFINITY == 0
# जर defined(HAVE_DECL___BUILTIN_INFF) && HAVE_DECL___BUILTIN_INFF == 1
#  define अनन्त __builtin_inff()
# endif
#endif

/*
 * Hack for systems that don't support FD passing: retain privileges
 * in the post-auth privsep process so it can allocate PTYs directly.
 *
 * Instead of doing what we did <= 9.7, which was to disable post-auth
 * privsep entirely, we run with temporarily_use_uid, restoring root
 * only to allocate ptys or in the child to permanently change UID.
 *
 * Cygwin doesn't need to drop privs here although it doesn't support
 * fd passing, as AFAIK PTY allocation on this platform doesn't require
 * special privileges to begin with.
 */
#जर defined(DISABLE_FD_PASSING) && !defined(HAVE_CYGWIN)
# define SKIP_PRIVDROP 1
#endif

#endif /* _DEFINES_H */
