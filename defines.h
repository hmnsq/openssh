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

#अगर_अघोषित _DEFINES_H
#घोषणा _DEFINES_H

/* Constants */

#अगर defined(HAVE_DECL_SHUT_RD) && HAVE_DECL_SHUT_RD == 0
क्रमागत
{
  SHUT_RD = 0,		/* No more receptions.  */
  SHUT_WR,			/* No more transmissions.  */
  SHUT_RDWR			/* No more receptions or transmissions.  */
};
# define SHUT_RD   SHUT_RD
# define SHUT_WR   SHUT_WR
# define SHUT_RDWR SHUT_RDWR
#पूर्ण_अगर

/*
 * Cygwin doesn't really have a notion of reserved ports.  It is still
 * is useful on the client side so for compatibility it defines as 1024 via
 * netinet/in.h inside an enum.  We * don't actually want that restriction
 * so we want to set that to zero, but we can't do it direct in config.h
 * because it'll cause a conflicting definition the first time we include
 * netinet/in.h.
 */

#अगर_घोषित HAVE_CYGWIN
#घोषणा IPPORT_RESERVED 0
#पूर्ण_अगर

/*
 * Definitions for IP type of service (ip_tos)
 */
#समावेश <netinet/ip.h>
#अगर_अघोषित IPTOS_LOWDELAY
# define IPTOS_LOWDELAY          0x10
# define IPTOS_THROUGHPUT        0x08
# define IPTOS_RELIABILITY       0x04
# define IPTOS_LOWCOST           0x02
# define IPTOS_MINCOST           IPTOS_LOWCOST
#पूर्ण_अगर /* IPTOS_LOWDELAY */

/*
 * Definitions for DiffServ Codepoints as per RFCs 2474, 3246, 4594 & 8622.
 * These are the 6 most significant bits as they appear on the wire, so the
 * two least significant bits must be zero.
 */
#अगर_अघोषित IPTOS_DSCP_AF11
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
#पूर्ण_अगर /* IPTOS_DSCP_AF11 */
#अगर_अघोषित IPTOS_DSCP_CS0
# define	IPTOS_DSCP_CS0		0x00
# define	IPTOS_DSCP_CS1		0x20
# define	IPTOS_DSCP_CS2		0x40
# define	IPTOS_DSCP_CS3		0x60
# define	IPTOS_DSCP_CS4		0x80
# define	IPTOS_DSCP_CS5		0xa0
# define	IPTOS_DSCP_CS6		0xc0
# define	IPTOS_DSCP_CS7		0xe0
#पूर्ण_अगर /* IPTOS_DSCP_CS0 */
#अगर_अघोषित IPTOS_DSCP_VA
# define	IPTOS_DSCP_VA		0xb0
#पूर्ण_अगर /* IPTOS_DSCP_VA */
#अगर_अघोषित IPTOS_DSCP_EF
# define	IPTOS_DSCP_EF		0xb8
#पूर्ण_अगर /* IPTOS_DSCP_EF */
#अगर_अघोषित IPTOS_DSCP_LE
# define	IPTOS_DSCP_LE		0x04
#पूर्ण_अगर /* IPTOS_DSCP_LE */
#अगर_अघोषित IPTOS_PREC_CRITIC_ECP
# define IPTOS_PREC_CRITIC_ECP		0xa0
#पूर्ण_अगर
#अगर_अघोषित IPTOS_PREC_INTERNETCONTROL
# define IPTOS_PREC_INTERNETCONTROL	0xc0
#पूर्ण_अगर
#अगर_अघोषित IPTOS_PREC_NETCONTROL
# define IPTOS_PREC_NETCONTROL		0xe0
#पूर्ण_अगर

#अगर_अघोषित PATH_MAX
# ifdef _POSIX_PATH_MAX
# define PATH_MAX _POSIX_PATH_MAX
# endif
#पूर्ण_अगर

#अगर_अघोषित MAXPATHLEN
# ifdef PATH_MAX
#  define MAXPATHLEN PATH_MAX
# अन्यथा /* PATH_MAX */
#  define MAXPATHLEN 64
# endif /* PATH_MAX */
#पूर्ण_अगर /* MAXPATHLEN */

#अगर_अघोषित HOST_NAME_MAX
# include "netdb.h" /* for MAXHOSTNAMELEN */
# अगर defined(_POSIX_HOST_NAME_MAX)
#  define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# elif defined(MAXHOSTNAMELEN)
#  define HOST_NAME_MAX MAXHOSTNAMELEN
# अन्यथा
#  define HOST_NAME_MAX	255
# endif
#पूर्ण_अगर /* HOST_NAME_MAX */

#अगर defined(HAVE_DECL_MAXSYMLINKS) && HAVE_DECL_MAXSYMLINKS == 0
# define MAXSYMLINKS 5
#पूर्ण_अगर

#अगर_अघोषित STDIN_FILENO
# define STDIN_FILENO    0
#पूर्ण_अगर
#अगर_अघोषित STDOUT_FILENO
# define STDOUT_FILENO   1
#पूर्ण_अगर
#अगर_अघोषित STDERR_FILENO
# define STDERR_FILENO   2
#पूर्ण_अगर

#अगर_अघोषित NGROUPS_MAX	/* Disable groupaccess if NGROUP_MAX is not set */
#अगर_घोषित NGROUPS
#घोषणा NGROUPS_MAX NGROUPS
#अन्यथा
#घोषणा NGROUPS_MAX 0
#पूर्ण_अगर
#पूर्ण_अगर

#अगर defined(HAVE_DECL_O_NONBLOCK) && HAVE_DECL_O_NONBLOCK == 0
# define O_NONBLOCK      00004	/* Non Blocking Open */
#पूर्ण_अगर

#अगर_अघोषित S_IFSOCK
# define S_IFSOCK 0
#पूर्ण_अगर /* S_IFSOCK */

#अगर_अघोषित S_ISDIR
# define S_ISDIR(mode)	(((mode) & (_S_IFMT)) == (_S_IFDIR))
#पूर्ण_अगर /* S_ISDIR */

#अगर_अघोषित S_ISREG
# define S_ISREG(mode)	(((mode) & (_S_IFMT)) == (_S_IFREG))
#पूर्ण_अगर /* S_ISREG */

#अगर_अघोषित S_ISLNK
# define S_ISLNK(mode)	(((mode) & S_IFMT) == S_IFLNK)
#पूर्ण_अगर /* S_ISLNK */

#अगर_अघोषित S_IXUSR
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
#पूर्ण_अगर /* S_IXUSR */

#अगर !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
#घोषणा MAP_ANON MAP_ANONYMOUS
#पूर्ण_अगर

#अगर_अघोषित MAP_FAILED
# define MAP_FAILED ((व्योम *)-1)
#पूर्ण_अगर

/*
SCO Open Server 3 has INADDR_LOOPBACK defined in rpc/rpc.h but
including rpc/rpc.h breaks Solaris 6
*/
#अगर_अघोषित INADDR_LOOPBACK
#घोषणा INADDR_LOOPBACK ((u_long)0x7f000001)
#पूर्ण_अगर

/* Types */

/* If sys/types.h does not supply intXX_t, supply them ourselves */
/* (or die trying) */

#अगर_अघोषित HAVE_U_INT
प्रकार अचिन्हित लघु u_short;
प्रकार अचिन्हित पूर्णांक u_int;
प्रकार अचिन्हित दीर्घ u_long;
#पूर्ण_अगर

#अगर_अघोषित HAVE_INTXX_T
प्रकार चिन्हित अक्षर int8_t;
# अगर (SIZEOF_SHORT_INT == 2)
प्रकार लघु पूर्णांक int16_t;
# अन्यथा
#   error "16 bit int type not found."
# endif
# अगर (SIZEOF_INT == 4)
प्रकार पूर्णांक int32_t;
# अन्यथा
#   error "32 bit int type not found."
# endif
#पूर्ण_अगर

/* If sys/types.h does not supply u_intXX_t, supply them ourselves */
#अगर_अघोषित HAVE_U_INTXX_T
# ifdef HAVE_UINTXX_T
प्रकार uint8_t u_int8_t;
प्रकार uint16_t u_int16_t;
प्रकार uint32_t u_int32_t;
# define HAVE_U_INTXX_T 1
# अन्यथा
प्रकार अचिन्हित अक्षर u_int8_t;
#  अगर (SIZEOF_SHORT_INT == 2)
प्रकार अचिन्हित लघु पूर्णांक u_int16_t;
#  अन्यथा
#    error "16 bit int type not found."
#  endif
#  अगर (SIZEOF_INT == 4)
प्रकार अचिन्हित पूर्णांक u_int32_t;
#  अन्यथा
#    error "32 bit int type not found."
#  endif
# endif
#घोषणा __BIT_TYPES_DEFINED__
#पूर्ण_अगर

#अगर !defined(LLONG_MIN) && defined(LONG_LONG_MIN)
#घोषणा LLONG_MIN LONG_LONG_MIN
#पूर्ण_अगर
#अगर !defined(LLONG_MAX) && defined(LONG_LONG_MAX)
#घोषणा LLONG_MAX LONG_LONG_MAX
#पूर्ण_अगर

#अगर_अघोषित UINT32_MAX
# अगर defined(HAVE_DECL_UINT32_MAX) && (HAVE_DECL_UINT32_MAX == 0)
#  अगर (SIZEOF_INT == 4)
#    define UINT32_MAX	अच_पूर्णांक_उच्च
#  endif
# endif
#पूर्ण_अगर

/* 64-bit types */
#अगर_अघोषित HAVE_INT64_T
# अगर (SIZEOF_LONG_INT == 8)
प्रकार दीर्घ पूर्णांक int64_t;
# अन्यथा
#  अगर (SIZEOF_LONG_LONG_INT == 8)
प्रकार दीर्घ दीर्घ पूर्णांक int64_t;
#  endif
# endif
#पूर्ण_अगर
#अगर_अघोषित HAVE_U_INT64_T
# अगर (SIZEOF_LONG_INT == 8)
प्रकार अचिन्हित दीर्घ पूर्णांक u_int64_t;
# अन्यथा
#  अगर (SIZEOF_LONG_LONG_INT == 8)
प्रकार अचिन्हित दीर्घ दीर्घ पूर्णांक u_int64_t;
#  endif
# endif
#पूर्ण_अगर

#अगर_अघोषित HAVE_UINTXX_T
प्रकार u_int8_t uint8_t;
प्रकार u_int16_t uint16_t;
प्रकार u_int32_t uint32_t;
प्रकार u_int64_t uint64_t;
#पूर्ण_अगर

#अगर_अघोषित HAVE_INTMAX_T
प्रकार दीर्घ दीर्घ intmax_t;
#पूर्ण_अगर

#अगर_अघोषित HAVE_UINTMAX_T
प्रकार अचिन्हित दीर्घ दीर्घ uintmax_t;
#पूर्ण_अगर

#अगर SIZEOF_TIME_T == SIZEOF_LONG_LONG_INT
# define SSH_TIME_T_MAX LLONG_MAX
#अन्यथा
# define SSH_TIME_T_MAX पूर्णांक_उच्च
#पूर्ण_अगर

#अगर_अघोषित HAVE_U_CHAR
प्रकार अचिन्हित अक्षर u_char;
# define HAVE_U_CHAR
#पूर्ण_अगर /* HAVE_U_CHAR */

#अगर_अघोषित ULLONG_MAX
# define ULLONG_MAX ((अचिन्हित दीर्घ दीर्घ)-1)
#पूर्ण_अगर

#अगर_अघोषित आकार_T_MAX
#घोषणा आकार_T_MAX अच_दीर्घ_उच्च
#पूर्ण_अगर /* SIZE_T_MAX */

#अगर_अघोषित HAVE_आकार_T
प्रकार अचिन्हित पूर्णांक माप_प्रकार;
# define HAVE_आकार_T
# define आकार_T_MAX अच_पूर्णांक_उच्च
#पूर्ण_अगर /* HAVE_SIZE_T */

#अगर_अघोषित SIZE_MAX
#घोषणा SIZE_MAX आकार_T_MAX
#पूर्ण_अगर

#अगर_अघोषित INT32_MAX
# अगर (SIZEOF_INT == 4)
#  define INT32_MAX पूर्णांक_उच्च
# elif (SIZEOF_LONG == 4)
#  define INT32_MAX दीर्घ_उच्च
# अन्यथा
#  error "need INT32_MAX"
# endif
#पूर्ण_अगर

#अगर_अघोषित INT64_MAX
# अगर (SIZEOF_INT == 8)
#  define INT64_MAX पूर्णांक_उच्च
# elif (SIZEOF_LONG == 8)
#  define INT64_MAX दीर्घ_उच्च
# elif (SIZEOF_LONG_LONG_INT == 8)
#  define INT64_MAX LLONG_MAX
# अन्यथा
#  error "need INT64_MAX"
# endif
#पूर्ण_अगर

#अगर_अघोषित HAVE_SSIZE_T
प्रकार पूर्णांक ssize_t;
#घोषणा SSIZE_MAX पूर्णांक_उच्च
# define HAVE_SSIZE_T
#पूर्ण_अगर /* HAVE_SSIZE_T */

#अगर_अघोषित HAVE_CLOCK_T
प्रकार दीर्घ घड़ी_प्रकार;
# define HAVE_CLOCK_T
#पूर्ण_अगर /* HAVE_CLOCK_T */

#अगर_अघोषित HAVE_SA_FAMILY_T
प्रकार पूर्णांक sa_family_t;
# define HAVE_SA_FAMILY_T
#पूर्ण_अगर /* HAVE_SA_FAMILY_T */

#अगर_अघोषित HAVE_PID_T
प्रकार पूर्णांक pid_t;
# define HAVE_PID_T
#पूर्ण_अगर /* HAVE_PID_T */

#अगर_अघोषित HAVE_SIG_ATOMIC_T
प्रकार पूर्णांक संक_पूर्ण_प्रकार;
# define HAVE_SIG_ATOMIC_T
#पूर्ण_अगर /* HAVE_SIG_ATOMIC_T */

#अगर_अघोषित HAVE_MODE_T
प्रकार पूर्णांक mode_t;
# define HAVE_MODE_T
#पूर्ण_अगर /* HAVE_MODE_T */

#अगर !defined(HAVE_SS_FAMILY_IN_SS) && defined(HAVE___SS_FAMILY_IN_SS)
# define ss_family __ss_family
#पूर्ण_अगर /* !defined(HAVE_SS_FAMILY_IN_SS) && defined(HAVE_SA_FAMILY_IN_SS) */

#अगर_अघोषित HAVE_SYS_UN_H
काष्ठा	sockaddr_un {
	लघु	sun_family;		/* AF_UNIX */
	अक्षर	sun_path[108];		/* path name (gag) */
};
#पूर्ण_अगर /* HAVE_SYS_UN_H */

#अगर_अघोषित HAVE_IN_ADDR_T
प्रकार u_int32_t	in_addr_t;
#पूर्ण_अगर
#अगर_अघोषित HAVE_IN_PORT_T
प्रकार u_int16_t	in_port_t;
#पूर्ण_अगर

#अगर defined(BROKEN_SYS_TERMIO_H) && !defined(_STRUCT_WINSIZE)
#घोषणा _STRUCT_WINSIZE
काष्ठा winsize {
      अचिन्हित लघु ws_row;          /* rows, in characters */
      अचिन्हित लघु ws_col;          /* columns, in character */
      अचिन्हित लघु ws_xpixel;       /* horizontal size, pixels */
      अचिन्हित लघु ws_ypixel;       /* vertical size, pixels */
};
#पूर्ण_अगर

/* bits needed for select that may not be in the system headers */
#अगर_अघोषित HAVE_FD_MASK
 प्रकार अचिन्हित दीर्घ पूर्णांक	fd_mask;
#पूर्ण_अगर

#अगर defined(HAVE_DECL_NFDBITS) && HAVE_DECL_NFDBITS == 0
# define	NFDBITS (8 * माप(अचिन्हित दीर्घ))
#पूर्ण_अगर

#अगर defined(HAVE_DECL_HOWMANY) && HAVE_DECL_HOWMANY == 0
# define howmany(x,y)	(((x)+((y)-1))/(y))
#पूर्ण_अगर

/* Paths */

#अगर_अघोषित _PATH_BSHELL
# define _PATH_BSHELL "/bin/sh"
#पूर्ण_अगर

#अगर_घोषित USER_PATH
# ifdef _PATH_STDPATH
#  undef _PATH_STDPATH
# endif
# define _PATH_STDPATH USER_PATH
#पूर्ण_अगर

#अगर_अघोषित _PATH_STDPATH
# define _PATH_STDPATH "/usr/bin:/bin:/usr/sbin:/sbin"
#पूर्ण_अगर

#अगर_अघोषित SUPERUSER_PATH
# define SUPERUSER_PATH	_PATH_STDPATH
#पूर्ण_अगर

#अगर_अघोषित _PATH_DEVNULL
# define _PATH_DEVNULL "/dev/null"
#पूर्ण_अगर

/* user may have set a different path */
#अगर defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY)
# undef _PATH_MAILDIR
#पूर्ण_अगर /* defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY) */

#अगर_घोषित MAIL_DIRECTORY
# define _PATH_MAILDIR MAIL_DIRECTORY
#पूर्ण_अगर

#अगर_अघोषित _PATH_NOLOGIN
# define _PATH_NOLOGIN "/etc/nologin"
#पूर्ण_अगर

/* Define this to be the path of the xauth program. */
#अगर_घोषित XAUTH_PATH
#घोषणा _PATH_XAUTH XAUTH_PATH
#पूर्ण_अगर /* XAUTH_PATH */

/* derived from XF4/xc/lib/dps/Xlibnet.h */
#अगर_अघोषित X_UNIX_PATH
#  ifdef __hpux
#    define X_UNIX_PATH "/var/spool/sockets/X11/%u"
#  अन्यथा
#    define X_UNIX_PATH "/tmp/.X11-unix/X%u"
#  endif
#पूर्ण_अगर /* X_UNIX_PATH */
#घोषणा _PATH_UNIX_X X_UNIX_PATH

#अगर_अघोषित _PATH_TTY
# define _PATH_TTY "/dev/tty"
#पूर्ण_अगर

/* Macros */

#अगर defined(HAVE_LOGIN_GETCAPBOOL) && defined(HAVE_LOGIN_CAP_H)
# define HAVE_LOGIN_CAP
#पूर्ण_अगर

#अगर_अघोषित MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
# define MIN(a,b) (((a)<(b))?(a):(b))
#पूर्ण_अगर

#अगर_अघोषित roundup
# define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#पूर्ण_अगर

#अगर_अघोषित timersub
#घोषणा timersub(a, b, परिणाम)					\
   करो {								\
      (परिणाम)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
      (परिणाम)->tv_usec = (a)->tv_usec - (b)->tv_usec;		\
      अगर ((परिणाम)->tv_usec < 0) {				\
	 --(परिणाम)->tv_sec;					\
	 (परिणाम)->tv_usec += 1000000;				\
      }								\
   } जबतक (0)
#पूर्ण_अगर

#अगर_अघोषित timespeccmp
#घोषणा	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#पूर्ण_अगर

#अगर_अघोषित TIMEVAL_TO_TIMESPEC
#घोषणा	TIMEVAL_TO_TIMESPEC(tv, ts) {					\
	(ts)->tv_sec = (tv)->tv_sec;					\
	(ts)->tv_nsec = (tv)->tv_usec * 1000;				\
}
#पूर्ण_अगर

#अगर_अघोषित TIMESPEC_TO_TIMEVAL
#घोषणा	TIMESPEC_TO_TIMEVAL(tv, ts) {					\
	(tv)->tv_sec = (ts)->tv_sec;					\
	(tv)->tv_usec = (ts)->tv_nsec / 1000;				\
}
#पूर्ण_अगर

#अगर_अघोषित timespeccmp
#घोषणा timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#पूर्ण_अगर

/* Operations on timespecs. */
#अगर_अघोषित timespecclear
#घोषणा	timespecclear(tsp)		(tsp)->tv_sec = (tsp)->tv_nsec = 0
#पूर्ण_अगर
#अगर_अघोषित timespeccmp
#घोषणा	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#पूर्ण_अगर
#अगर_अघोषित timespecadd
#घोषणा	timespecadd(tsp, usp, vsp)					\
	करो {								\
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;	\
		अगर ((vsp)->tv_nsec >= 1000000000L) {			\
			(vsp)->tv_sec++;				\
			(vsp)->tv_nsec -= 1000000000L;			\
		}							\
	} जबतक (0)
#पूर्ण_अगर
#अगर_अघोषित timespecsub
#घोषणा	timespecsub(tsp, usp, vsp)					\
	करो {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		अगर ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} जबतक (0)
#पूर्ण_अगर

#अगर_अघोषित __P
# define __P(x) x
#पूर्ण_अगर

#अगर !defined(IN6_IS_ADDR_V4MAPPED)
# define IN6_IS_ADDR_V4MAPPED(a) \
	((((u_int32_t *) (a))[0] == 0) && (((u_int32_t *) (a))[1] == 0) && \
	 (((u_int32_t *) (a))[2] == htonl (0xffff)))
#पूर्ण_अगर /* !defined(IN6_IS_ADDR_V4MAPPED) */

#अगर !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#पूर्ण_अगर /* !defined(__GNUC__) || (__GNUC__ < 2) */

#अगर !defined(HAVE_ATTRIBUTE__SENTINEL__) && !defined(__sentinel__)
# define __sentinel__
#पूर्ण_अगर

#अगर !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__bounded__)
# define __bounded__(x, y, z)
#पूर्ण_अगर

#अगर !defined(HAVE_ATTRIBUTE__NONNULL__) && !defined(__nonnull__)
# define __nonnull__(x)
#पूर्ण_अगर

#अगर !defined(HAVE_ATTRIBUTE__NONSTRING__) && !defined(__nonstring__)
# define __nonstring__
#पूर्ण_अगर

#अगर_अघोषित OSSH_ALIGNBYTES
#घोषणा OSSH_ALIGNBYTES	(माप(पूर्णांक) - 1)
#पूर्ण_अगर
#अगर_अघोषित __CMSG_ALIGN
#घोषणा	__CMSG_ALIGN(p) (((u_int)(p) + OSSH_ALIGNBYTES) &~ OSSH_ALIGNBYTES)
#पूर्ण_अगर

/* Length of the contents of a control message of length len */
#अगर_अघोषित CMSG_LEN
#घोषणा	CMSG_LEN(len)	(__CMSG_ALIGN(माप(काष्ठा cmsghdr)) + (len))
#पूर्ण_अगर

/* Length of the space taken up by a padded control message of length len */
#अगर_अघोषित CMSG_SPACE
#घोषणा	CMSG_SPACE(len)	(__CMSG_ALIGN(माप(काष्ठा cmsghdr)) + __CMSG_ALIGN(len))
#पूर्ण_अगर

/* given pointer to struct cmsghdr, return pointer to data */
#अगर_अघोषित CMSG_DATA
#घोषणा CMSG_DATA(cmsg) ((u_char *)(cmsg) + __CMSG_ALIGN(माप(काष्ठा cmsghdr)))
#पूर्ण_अगर /* CMSG_DATA */

/*
 * RFC 2292 requires to check msg_controllen, in case that the kernel returns
 * an empty list for some reasons.
 */
#अगर_अघोषित CMSG_FIRSTHDR
#घोषणा CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= माप(काष्ठा cmsghdr) ? \
	 (काष्ठा cmsghdr *)(mhdr)->msg_control : \
	 (काष्ठा cmsghdr *)शून्य)
#पूर्ण_अगर /* CMSG_FIRSTHDR */

#अगर defined(HAVE_DECL_OFFSETOF) && HAVE_DECL_OFFSETOF == 0
# define दुरत्व(type, member) ((माप_प्रकार) &((type *)0)->member)
#पूर्ण_अगर

/* Set up BSD-style BYTE_ORDER definition if it isn't there already */
/* XXX: doesn't try to cope with strange byte orders (PDP_ENDIAN) */
#अगर_अघोषित BYTE_ORDER
# ifndef LITTLE_ENDIAN
#  define LITTLE_ENDIAN  1234
# endif /* LITTLE_ENDIAN */
# ifndef BIG_ENDIAN
#  define BIG_ENDIAN     4321
# endif /* BIG_ENDIAN */
# ifdef शब्दगण_BIGENDIAN
#  define BYTE_ORDER BIG_ENDIAN
# अन्यथा /* WORDS_BIGENDIAN */
#  define BYTE_ORDER LITTLE_ENDIAN
# endif /* WORDS_BIGENDIAN */
#पूर्ण_अगर /* BYTE_ORDER */

#अगर (defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0) || \
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
# ifdef शब्दगण_BIGENDIAN
#  अगर defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) (openssh_swap32(v))
#  endif
#  अगर defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#   define le64toh(v) (openssh_swap64(v))
#  endif
#  अगर defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) (openssh_swap64(v))
#  endif
#  अगर defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) ((uint32_t)v)
#  endif
# अन्यथा
#  अगर defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) ((uint32_t)v)
#  endif
#  अगर defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#    define le64toh(v) ((uint64_t)v)
#  endif
#  अगर defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) ((uint64_t)v)
#  endif
#  अगर defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) (openssh_swap32(v))
#  endif
# endif
#पूर्ण_अगर

/* Function replacement / compatibility hacks */

#अगर !defined(HAVE_GETADDRINFO) && (defined(HAVE_OGETADDRINFO) || defined(HAVE_NGETADDRINFO))
# define HAVE_GETADDRINFO
#पूर्ण_अगर

#अगर_अघोषित HAVE_GETOPT_OPTRESET
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
#पूर्ण_अगर

#अगर defined(BROKEN_GETADDRINFO) && defined(HAVE_GETADDRINFO)
# undef HAVE_GETADDRINFO
#पूर्ण_अगर
#अगर defined(BROKEN_GETADDRINFO) && defined(HAVE_FREEADDRINFO)
# undef HAVE_FREEADDRINFO
#पूर्ण_अगर
#अगर defined(BROKEN_GETADDRINFO) && defined(HAVE_GAI_STRERROR)
# undef HAVE_GAI_STRERROR
#पूर्ण_अगर

#अगर defined(HAVE_GETADDRINFO)
# अगर defined(HAVE_DECL_AI_NUMERICSERV) && HAVE_DECL_AI_NUMERICSERV == 0
#   define AI_NUMERICSERV	0
# endif
#पूर्ण_अगर

#अगर defined(BROKEN_UPDWTMPX) && defined(HAVE_UPDWTMPX)
# undef HAVE_UPDWTMPX
#पूर्ण_अगर

#अगर defined(BROKEN_SHADOW_EXPIRE) && defined(HAS_SHADOW_EXPIRE)
# undef HAS_SHADOW_EXPIRE
#पूर्ण_अगर

#अगर defined(HAVE_OPENLOG_R) && defined(SYSLOG_तथ्य_INIT) && \
    defined(SYSLOG_R_SAFE_IN_SIGHAND)
# define DO_LOG_SAFE_IN_SIGHAND
#पूर्ण_अगर

#अगर !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY)
# define स_हटाओ(s1, s2, n) bcopy((s2), (s1), (n))
#पूर्ण_अगर /* !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY) */

#अगर_अघोषित GETPGRP_VOID
# include <unistd.h>
# define getpgrp() getpgrp(0)
#पूर्ण_अगर

#अगर_घोषित USE_BSM_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#पूर्ण_अगर

#अगर_घोषित USE_LINUX_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#पूर्ण_अगर

#अगर !defined(HAVE___func__) && defined(HAVE___FUNCTION__)
#  define __func__ __FUNCTION__
#या_अगर !defined(HAVE___func__)
#  define __func__ ""
#पूर्ण_अगर

#अगर defined(KRB5) && !defined(HEIMDAL)
#  define krb5_get_err_text(context,code) error_message(code)
#पूर्ण_अगर

/* Maximum number of file descriptors available */
#अगर_घोषित HAVE_SYSCONF
# define SSH_SYSFDMAX sysconf(_SC_OPEN_MAX)
#अन्यथा
# define SSH_SYSFDMAX 10000
#पूर्ण_अगर

#अगर_घोषित FSID_HAS_VAL
/* encode f_fsid into a 64 bit value  */
#घोषणा FSID_TO_ULONG(f) \
	((((u_int64_t)(f).val[0] & 0xffffffffUL) << 32) | \
	    ((f).val[1] & 0xffffffffUL))
#या_अगर defined(FSID_HAS___VAL)
#घोषणा FSID_TO_ULONG(f) \
	((((u_int64_t)(f).__val[0] & 0xffffffffUL) << 32) | \
	    ((f).__val[1] & 0xffffffffUL))
#अन्यथा
# define FSID_TO_ULONG(f) ((f))
#पूर्ण_अगर

#अगर defined(__Lynx__)
 /*
  * LynxOS defines these in param.h which we do not want to include since
  * it will also pull in a bunch of kernel definitions.
  */
# define ALIGNBYTES (माप(पूर्णांक) - 1)
# define ALIGN(p) (((अचिन्हित)p + ALIGNBYTES) & ~ALIGNBYTES)
  /* Missing prototypes on LynxOS */
  पूर्णांक snprintf (अक्षर *, माप_प्रकार, स्थिर अक्षर *, ...);
  पूर्णांक mkstemp (अक्षर *);
  अक्षर *crypt (स्थिर अक्षर *, स्थिर अक्षर *);
  पूर्णांक seteuid (uid_t);
  पूर्णांक setegid (gid_t);
  अक्षर *mkdtemp (अक्षर *);
  पूर्णांक rresvport_af (पूर्णांक *, sa_family_t);
  पूर्णांक innetgr (स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *);
#पूर्ण_अगर

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
#अगर_अघोषित UTMP_FILE
#  ifdef _PATH_UTMP
#    define UTMP_FILE _PATH_UTMP
#  अन्यथा
#    ifdef CONF_UTMP_FILE
#      define UTMP_FILE CONF_UTMP_FILE
#    endif
#  endif
#पूर्ण_अगर
#अगर_अघोषित WTMP_FILE
#  ifdef _PATH_WTMP
#    define WTMP_FILE _PATH_WTMP
#  अन्यथा
#    ifdef CONF_WTMP_FILE
#      define WTMP_FILE CONF_WTMP_FILE
#    endif
#  endif
#पूर्ण_अगर
/* pick up the user's location for lastlog if given */
#अगर_अघोषित LASTLOG_FILE
#  ifdef _PATH_LASTLOG
#    define LASTLOG_FILE _PATH_LASTLOG
#  अन्यथा
#    ifdef CONF_LASTLOG_FILE
#      define LASTLOG_FILE CONF_LASTLOG_FILE
#    endif
#  endif
#पूर्ण_अगर

#अगर defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
# define USE_SHADOW
#पूर्ण_अगर

/* The login() library function in libutil is first choice */
#अगर defined(HAVE_LOGIN) && !defined(DISABLE_LOGIN)
#  define USE_LOGIN

#अन्यथा
/* Simply select your favourite login types. */
/* Can't do if-else because some systems use several... <sigh> */
#  अगर !defined(DISABLE_UTMPX)
#    define USE_UTMPX
#  endif
#  अगर defined(UTMP_FILE) && !defined(DISABLE_UTMP)
#    define USE_UTMP
#  endif
#  अगर defined(WTMPX_FILE) && !defined(DISABLE_WTMPX)
#    define USE_WTMPX
#  endif
#  अगर defined(WTMP_FILE) && !defined(DISABLE_WTMP)
#    define USE_WTMP
#  endif

#पूर्ण_अगर

#अगर_अघोषित UT_LINESIZE
# define UT_LINESIZE 8
#पूर्ण_अगर

/* I hope that the presence of LASTLOG_FILE is enough to detect this */
#अगर defined(LASTLOG_FILE) && !defined(DISABLE_LASTLOG)
#  define USE_LASTLOG
#पूर्ण_अगर

#अगर_घोषित HAVE_OSF_SIA
# ifdef USE_SHADOW
#  undef USE_SHADOW
# endif
# define CUSTOM_SYS_AUTH_PASSWD 1
#पूर्ण_अगर

#अगर defined(HAVE_LIBIAF) && defined(HAVE_SET_ID) && !defined(HAVE_SECUREWARE)
# define CUSTOM_SYS_AUTH_PASSWD 1
#पूर्ण_अगर
#अगर defined(HAVE_LIBIAF) && defined(HAVE_SET_ID) && !defined(BROKEN_LIBIAF)
# define USE_LIBIAF
#पूर्ण_अगर

/* HP-UX 11.11 */
#अगर_घोषित BTMP_FILE
# define _PATH_BTMP BTMP_FILE
#पूर्ण_अगर

#अगर defined(USE_BTMP) && defined(_PATH_BTMP)
# define CUSTOM_FAILED_LOGIN
#पूर्ण_अगर

/** end of login recorder definitions */

#अगर_घोषित BROKEN_GETGROUPS
# define getgroups(a,b) ((a)==0 && (b)==शून्य ? NGROUPS_MAX : getgroups((a),(b)))
#पूर्ण_अगर

#अगर_अघोषित IOV_MAX
# अगर defined(_XOPEN_IOV_MAX)
#  define	IOV_MAX		_XOPEN_IOV_MAX
# elif defined(DEF_IOV_MAX)
#  define	IOV_MAX		DEF_IOV_MAX
# अन्यथा
#  define	IOV_MAX		16
# endif
#पूर्ण_अगर

#अगर_अघोषित EWOULDBLOCK
# define EWOULDBLOCK EAGAIN
#पूर्ण_अगर

#अगर_अघोषित INET6_ADDRSTRLEN	/* for non IPv6 machines */
#घोषणा INET6_ADDRSTRLEN 46
#पूर्ण_अगर

#अगर_अघोषित SSH_IOBUFSZ
# define SSH_IOBUFSZ 8192
#पूर्ण_अगर

/*
 * We want functions in openbsd-compat, if enabled, to override system ones.
 * We no-op out the weak symbol definition rather than remove it to reduce
 * future sync problems.  Some compilers (eg Unixware) do not allow an
 * empty statement, so we use a bogus function declaration.
 */
#घोषणा DEF_WEAK(x)	व्योम __ssh_compat_weak_##x(व्योम)

/*
 * Platforms that have arc4random_uniform() and not arc4random_stir()
 * shouldn't need the latter.
 */
#अगर defined(HAVE_ARC4RANDOM) && defined(HAVE_ARC4RANDOM_UNIFORM) && \
    !defined(HAVE_ARC4RANDOM_STIR)
# define arc4random_stir()
#पूर्ण_अगर

#अगर_अघोषित HAVE_VA_COPY
# ifdef HAVE___VA_COPY
#  define va_copy(dest, src) __va_copy(dest, src)
# अन्यथा
#  define va_copy(dest, src) (dest) = (src)
# endif
#पूर्ण_अगर

#अगर_अघोषित __predict_true
# अगर defined(__GNUC__) && \
     ((__GNUC__ > (2)) || (__GNUC__ == (2) && __GNUC_MINOR__ >= (96)))
#  define __predict_true(exp)     __builtin_expect(((exp) != 0), 1)
#  define __predict_false(exp)    __builtin_expect(((exp) != 0), 0)
# अन्यथा
#  define __predict_true(exp)     ((exp) != 0)
#  define __predict_false(exp)    ((exp) != 0)
# endif /* gcc version */
#पूर्ण_अगर /* __predict_true */

/*
 * sntrup761 uses variable length arrays and c99-style declarations after code,
 * so only enable if the compiler supports them.
 */
#अगर defined(VARIABLE_लंबाई_ARRAYS) && defined(VARIABLE_DECLARATION_AFTER_CODE)
# define USE_SNTRUP761X25519	1
/* The ML-KEM768 and ML-DSA implementations also uses C89 features */
# define USE_MLKEM768X25519	1
# define USE_MLDSA		1
#पूर्ण_अगर

#अगर defined(HAVE_DECL_INFINITY) && HAVE_DECL_INFINITY == 0
# अगर defined(HAVE_DECL___BUILTIN_INFF) && HAVE_DECL___BUILTIN_INFF == 1
#  define अनन्त __builtin_inff()
# endif
#पूर्ण_अगर

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
#अगर defined(DISABLE_FD_PASSING) && !defined(HAVE_CYGWIN)
# define SKIP_PRIVDROP 1
#पूर्ण_अगर

#पूर्ण_अगर /* _DEFINES_H */
