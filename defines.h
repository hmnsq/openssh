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

#यदि_अपरिभाषितम् परिभाषते_H
#परिभाषय परिभाषते_H

/* Constants */

#यदि defined(HAVE_DECL_SHUT_RD) && HAVE_DECL_SHUT_RD == 0
गणना
{
  SHUT_RD = 0,		/* No more receptions.  */
  SHUT_WR,			/* No more transmissions.  */
  SHUT_RDWR			/* No more receptions or transmissions.  */
};
# define SHUT_RD   SHUT_RD
# define SHUT_WR   SHUT_WR
# define SHUT_RDWR SHUT_RDWR
#यदि_अन्तः

/*
 * Cygwin doesn't really have a notion of reserved ports.  It is still
 * is useful on the client side so for compatibility it defines as 1024 via
 * netinet/in.h inside an enum.  We * don't actually want that restriction
 * so we want to set that to zero, but we can't do it direct in config.h
 * because it'll cause a conflicting definition the first time we include
 * netinet/in.h.
 */

#यदि_परिभाषितम् HAVE_CYGWIN
#परिभाषय IPPORT_RESERVED 0
#यदि_अन्तः

/*
 * Definitions for IP type of service (ip_tos)
 */
#अन्तर्भाव <netinet/ip.h>
#यदि_अपरिभाषितम् IPTOS_LOWDELAY
# define IPTOS_LOWDELAY          0x10
# define IPTOS_THROUGHPUT        0x08
# define IPTOS_RELIABILITY       0x04
# define IPTOS_LOWCOST           0x02
# define IPTOS_MINCOST           IPTOS_LOWCOST
#यदि_अन्तः /* IPTOS_LOWDELAY */

/*
 * Definitions for DiffServ Codepoints as per RFCs 2474, 3246, 4594 & 8622.
 * These are the 6 most significant bits as they appear on the wire, so the
 * two least significant bits must be zero.
 */
#यदि_अपरिभाषितम् IPTOS_DSCP_AF11
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
#यदि_अन्तः /* IPTOS_DSCP_AF11 */
#यदि_अपरिभाषितम् IPTOS_DSCP_CS0
# define	IPTOS_DSCP_CS0		0x00
# define	IPTOS_DSCP_CS1		0x20
# define	IPTOS_DSCP_CS2		0x40
# define	IPTOS_DSCP_CS3		0x60
# define	IPTOS_DSCP_CS4		0x80
# define	IPTOS_DSCP_CS5		0xa0
# define	IPTOS_DSCP_CS6		0xc0
# define	IPTOS_DSCP_CS7		0xe0
#यदि_अन्तः /* IPTOS_DSCP_CS0 */
#यदि_अपरिभाषितम् IPTOS_DSCP_VA
# define	IPTOS_DSCP_VA		0xb0
#यदि_अन्तः /* IPTOS_DSCP_VA */
#यदि_अपरिभाषितम् IPTOS_DSCP_EF
# define	IPTOS_DSCP_EF		0xb8
#यदि_अन्तः /* IPTOS_DSCP_EF */
#यदि_अपरिभाषितम् IPTOS_DSCP_LE
# define	IPTOS_DSCP_LE		0x04
#यदि_अन्तः /* IPTOS_DSCP_LE */
#यदि_अपरिभाषितम् IPTOS_PREC_CRITIC_ECP
# define IPTOS_PREC_CRITIC_ECP		0xa0
#यदि_अन्तः
#यदि_अपरिभाषितम् IPTOS_PREC_INTERNETCONTROL
# define IPTOS_PREC_INTERNETCONTROL	0xc0
#यदि_अन्तः
#यदि_अपरिभाषितम् IPTOS_PREC_NETCONTROL
# define IPTOS_PREC_NETCONTROL		0xe0
#यदि_अन्तः

#यदि_अपरिभाषितम् PATH_MAX
# ifdef _POSIX_PATH_MAX
# define PATH_MAX _POSIX_PATH_MAX
# endif
#यदि_अन्तः

#यदि_अपरिभाषितम् MAXPATHLEN
# ifdef PATH_MAX
#  define MAXPATHLEN PATH_MAX
# अन्यथा /* PATH_MAX */
#  define MAXPATHLEN 64
# endif /* PATH_MAX */
#यदि_अन्तः /* MAXPATHLEN */

#यदि_अपरिभाषितम् HOST_NAME_MAX
# include "netdb.h" /* for MAXHOSTNAMELEN */
# यदि defined(_POSIX_HOST_NAME_MAX)
#  define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# elif defined(MAXHOSTNAMELEN)
#  define HOST_NAME_MAX MAXHOSTNAMELEN
# अन्यथा
#  define HOST_NAME_MAX	255
# endif
#यदि_अन्तः /* HOST_NAME_MAX */

#यदि defined(HAVE_DECL_MAXSYMLINKS) && HAVE_DECL_MAXSYMLINKS == 0
# define MAXSYMLINKS 5
#यदि_अन्तः

#यदि_अपरिभाषितम् STDIN_FILENO
# define STDIN_FILENO    0
#यदि_अन्तः
#यदि_अपरिभाषितम् STDOUT_FILENO
# define STDOUT_FILENO   1
#यदि_अन्तः
#यदि_अपरिभाषितम् STDERR_FILENO
# define STDERR_FILENO   2
#यदि_अन्तः

#यदि_अपरिभाषितम् NGROUPS_MAX	/* Disable groupaccess if NGROUP_MAX is not set */
#यदि_परिभाषितम् NGROUPS
#परिभाषय NGROUPS_MAX NGROUPS
#अन्यथा
#परिभाषय NGROUPS_MAX 0
#यदि_अन्तः
#यदि_अन्तः

#यदि defined(HAVE_DECL_O_NONBLOCK) && HAVE_DECL_O_NONBLOCK == 0
# define O_NONBLOCK      00004	/* Non Blocking Open */
#यदि_अन्तः

#यदि_अपरिभाषितम् S_IFSOCK
# define S_IFSOCK 0
#यदि_अन्तः /* S_IFSOCK */

#यदि_अपरिभाषितम् S_ISDIR
# define S_ISDIR(बहुलकम्)	(((बहुलकम्) & (_S_IFMT)) == (_S_IFDIR))
#यदि_अन्तः /* S_ISDIR */

#यदि_अपरिभाषितम् S_ISREG
# define S_ISREG(बहुलकम्)	(((बहुलकम्) & (_S_IFMT)) == (_S_IFREG))
#यदि_अन्तः /* S_ISREG */

#यदि_अपरिभाषितम् S_ISLNK
# define S_ISLNK(बहुलकम्)	(((बहुलकम्) & S_IFMT) == S_IFLNK)
#यदि_अन्तः /* S_ISLNK */

#यदि_अपरिभाषितम् S_IXUSR
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
#यदि_अन्तः /* S_IXUSR */

#यदि !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
#परिभाषय MAP_ANON MAP_ANONYMOUS
#यदि_अन्तः

#यदि_अपरिभाषितम् MAP_FAILED
# define MAP_FAILED ((शून्य *)-1)
#यदि_अन्तः

/*
SCO Open Server 3 has INADDR_LOOPBACK defined in rpc/rpc.h but
including rpc/rpc.h breaks Solaris 6
*/
#यदि_अपरिभाषितम् INADDR_LOOPBACK
#परिभाषय INADDR_LOOPBACK ((u_long)0x7f000001)
#यदि_अन्तः

/* Types */

/* If sys/types.h does not supply intXX_t, supply them ourselves */
/* (or die trying) */

#यदि_अपरिभाषितम् HAVE_U_INT
प्रकारनिर्देश अचिह्नित ह्रस्व u_short;
प्रकारनिर्देश अचिह्नित पूर्णाङ्क u_int;
प्रकारनिर्देश अचिह्नित दीर्घ u_long;
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_INTXX_T
प्रकारनिर्देश चिह्नित वर्ण int8_t;
# यदि (SIZEOF_SHORT_INT == 2)
प्रकारनिर्देश ह्रस्व पूर्णाङ्क int16_t;
# अन्यथा
#   error "16 bit int type not found."
# endif
# यदि (SIZEOF_INT == 4)
प्रकारनिर्देश पूर्णाङ्क int32_t;
# अन्यथा
#   error "32 bit int type not found."
# endif
#यदि_अन्तः

/* If sys/types.h does not supply u_intXX_t, supply them ourselves */
#यदि_अपरिभाषितम् HAVE_U_INTXX_T
# ifdef HAVE_UINTXX_T
प्रकारनिर्देश uint8_t u_int8_t;
प्रकारनिर्देश uint16_t u_int16_t;
प्रकारनिर्देश uint32_t u_int32_t;
# define HAVE_U_INTXX_T 1
# अन्यथा
प्रकारनिर्देश अचिह्नित वर्ण u_int8_t;
#  यदि (SIZEOF_SHORT_INT == 2)
प्रकारनिर्देश अचिह्नित ह्रस्व पूर्णाङ्क u_int16_t;
#  अन्यथा
#    error "16 bit int type not found."
#  endif
#  यदि (SIZEOF_INT == 4)
प्रकारनिर्देश अचिह्नित पूर्णाङ्क u_int32_t;
#  अन्यथा
#    error "32 bit int type not found."
#  endif
# endif
#परिभाषय __BIT_TYPES_DEFINED__
#यदि_अन्तः

#यदि !defined(LLONG_MIN) && defined(LONG_LONG_MIN)
#परिभाषय LLONG_MIN LONG_LONG_MIN
#यदि_अन्तः
#यदि !defined(LLONG_MAX) && defined(LONG_LONG_MAX)
#परिभाषय LLONG_MAX LONG_LONG_MAX
#यदि_अन्तः

#यदि_अपरिभाषितम् UINT32_MAX
# यदि defined(HAVE_DECL_UINT32_MAX) && (HAVE_DECL_UINT32_MAX == 0)
#  यदि (SIZEOF_INT == 4)
#    define UINT32_MAX	UINT_MAX
#  endif
# endif
#यदि_अन्तः

/* 64-bit types */
#यदि_अपरिभाषितम् HAVE_INT64_T
# यदि (SIZEOF_LONG_INT == 8)
प्रकारनिर्देश दीर्घ पूर्णाङ्क int64_t;
# अन्यथा
#  यदि (SIZEOF_LONG_LONG_INT == 8)
प्रकारनिर्देश दीर्घ दीर्घ पूर्णाङ्क int64_t;
#  endif
# endif
#यदि_अन्तः
#यदि_अपरिभाषितम् HAVE_U_INT64_T
# यदि (SIZEOF_LONG_INT == 8)
प्रकारनिर्देश अचिह्नित दीर्घ पूर्णाङ्क u_int64_t;
# अन्यथा
#  यदि (SIZEOF_LONG_LONG_INT == 8)
प्रकारनिर्देश अचिह्नित दीर्घ दीर्घ पूर्णाङ्क u_int64_t;
#  endif
# endif
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_UINTXX_T
प्रकारनिर्देश u_int8_t uint8_t;
प्रकारनिर्देश u_int16_t uint16_t;
प्रकारनिर्देश u_int32_t uint32_t;
प्रकारनिर्देश u_int64_t uint64_t;
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_INTMAX_T
प्रकारनिर्देश दीर्घ दीर्घ intmax_t;
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_UINTMAX_T
प्रकारनिर्देश अचिह्नित दीर्घ दीर्घ uintmax_t;
#यदि_अन्तः

#यदि SIZEOF_TIME_T == SIZEOF_LONG_LONG_INT
# define SSH_TIME_T_MAX LLONG_MAX
#अन्यथा
# define SSH_TIME_T_MAX अधिकतम_पूर्णाङ्कः
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_U_CHAR
प्रकारनिर्देश अचिह्नित वर्ण u_char;
# define HAVE_U_CHAR
#यदि_अन्तः /* HAVE_U_CHAR */

#यदि_अपरिभाषितम् ULLONG_MAX
# define ULLONG_MAX ((अचिह्नित दीर्घ दीर्घ)-1)
#यदि_अन्तः

#यदि_अपरिभाषितम् आकार_T_MAX
#परिभाषय आकार_T_MAX ULONG_MAX
#यदि_अन्तः /* SIZE_T_MAX */

#यदि_अपरिभाषितम् HAVE_आकार_T
प्रकारनिर्देश अचिह्नित पूर्णाङ्क आकार_t;
# define HAVE_आकार_T
# define आकार_T_MAX UINT_MAX
#यदि_अन्तः /* HAVE_SIZE_T */

#यदि_अपरिभाषितम् SIZE_MAX
#परिभाषय SIZE_MAX आकार_T_MAX
#यदि_अन्तः

#यदि_अपरिभाषितम् INT32_MAX
# यदि (SIZEOF_INT == 4)
#  define INT32_MAX अधिकतम_पूर्णाङ्कः
# elif (SIZEOF_LONG == 4)
#  define INT32_MAX LONG_MAX
# अन्यथा
#  error "need INT32_MAX"
# endif
#यदि_अन्तः

#यदि_अपरिभाषितम् INT64_MAX
# यदि (SIZEOF_INT == 8)
#  define INT64_MAX अधिकतम_पूर्णाङ्कः
# elif (SIZEOF_LONG == 8)
#  define INT64_MAX LONG_MAX
# elif (SIZEOF_LONG_LONG_INT == 8)
#  define INT64_MAX LLONG_MAX
# अन्यथा
#  error "need INT64_MAX"
# endif
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_SSIZE_T
प्रकारनिर्देश पूर्णाङ्क ssize_t;
#परिभाषय SSIZE_MAX अधिकतम_पूर्णाङ्कः
# define HAVE_SSIZE_T
#यदि_अन्तः /* HAVE_SSIZE_T */

#यदि_अपरिभाषितम् HAVE_CLOCK_T
प्रकारनिर्देश दीर्घ clock_t;
# define HAVE_CLOCK_T
#यदि_अन्तः /* HAVE_CLOCK_T */

#यदि_अपरिभाषितम् HAVE_SA_FAMILY_T
प्रकारनिर्देश पूर्णाङ्क sa_family_t;
# define HAVE_SA_FAMILY_T
#यदि_अन्तः /* HAVE_SA_FAMILY_T */

#यदि_अपरिभाषितम् HAVE_PID_T
प्रकारनिर्देश पूर्णाङ्क pid_t;
# define HAVE_PID_T
#यदि_अन्तः /* HAVE_PID_T */

#यदि_अपरिभाषितम् HAVE_SIG_ATOMIC_T
प्रकारनिर्देश पूर्णाङ्क sig_atomic_t;
# define HAVE_SIG_ATOMIC_T
#यदि_अन्तः /* HAVE_SIG_ATOMIC_T */

#यदि_अपरिभाषितम् HAVE_बहुलकम्_T
प्रकारनिर्देश पूर्णाङ्क बहुलकम्_t;
# define HAVE_बहुलकम्_T
#यदि_अन्तः /* HAVE_MODE_T */

#यदि !defined(HAVE_SS_FAMILY_अन्तर्_SS) && defined(HAVE_SS_FAMILY_अन्तर्_SS_2)
# define ss_family __ss_family
#यदि_अन्तः /* !defined(HAVE_SS_FAMILY_IN_SS) && defined(HAVE_SA_FAMILY_IN_SS) */

#यदि_अपरिभाषितम् HAVE_SYS_UN_H
संरचना	sockaddr_un {
	ह्रस्व	sun_family;		/* AF_UNIX */
	वर्ण	sun_मार्गः[108];		/* path name (gag) */
};
#यदि_अन्तः /* HAVE_SYS_UN_H */

#यदि_अपरिभाषितम् HAVE_अन्तर्_ADDR_T
प्रकारनिर्देश u_int32_t	in_addr_t;
#यदि_अन्तः
#यदि_अपरिभाषितम् HAVE_अन्तर्_पत्तनम्_T
प्रकारनिर्देश u_int16_t	in_port_t;
#यदि_अन्तः

#यदि defined(BROKEN_SYS_TERMIO_H) && !defined(_STRUCT_WINSIZE)
#परिभाषय _STRUCT_WINSIZE
संरचना winsize {
      अचिह्नित ह्रस्व ws_row;          /* rows, in characters */
      अचिह्नित ह्रस्व ws_col;          /* columns, in character */
      अचिह्नित ह्रस्व ws_xpixel;       /* horizontal size, pixels */
      अचिह्नित ह्रस्व ws_ypixel;       /* vertical size, pixels */
};
#यदि_अन्तः

/* bits needed for select that may not be in the system headers */
#यदि_अपरिभाषितम् HAVE_FD_आवरणम्
 प्रकारनिर्देश अचिह्नित दीर्घ पूर्णाङ्क	fd_आवरणम्;
#यदि_अन्तः

#यदि defined(HAVE_DECL_NFDBITS) && HAVE_DECL_NFDBITS == 0
# define	NFDBITS (8 * परिमाण(अचिह्नित दीर्घ))
#यदि_अन्तः

#यदि defined(HAVE_DECL_HOWMANY) && HAVE_DECL_HOWMANY == 0
# define howmany(x,y)	(((x)+((y)-1))/(y))
#यदि_अन्तः

/* Paths */

#यदि_अपरिभाषितम् _PATH_BSHELL
# define _PATH_BSHELL "/bin/sh"
#यदि_अन्तः

#यदि_परिभाषितम् USER_मार्गः
# ifdef _PATH_STDPATH
#  undef _PATH_STDPATH
# endif
# define _PATH_STDPATH USER_मार्गः
#यदि_अन्तः

#यदि_अपरिभाषितम् _PATH_STDPATH
# define _PATH_STDPATH "/usr/bin:/bin:/usr/sbin:/sbin"
#यदि_अन्तः

#यदि_अपरिभाषितम् SUPERUSER_मार्गः
# define SUPERUSER_मार्गः	_PATH_STDPATH
#यदि_अन्तः

#यदि_अपरिभाषितम् _PATH_DEVNULL
# define _PATH_DEVNULL "/dev/null"
#यदि_अन्तः

/* user may have set a different path */
#यदि defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY)
# undef _PATH_MAILDIR
#यदि_अन्तः /* defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY) */

#यदि_परिभाषितम् MAIL_DIRECTORY
# define _PATH_MAILDIR MAIL_DIRECTORY
#यदि_अन्तः

#यदि_अपरिभाषितम् _PATH_NOLOGIN
# define _PATH_NOLOGIN "/etc/nologin"
#यदि_अन्तः

/* Define this to be the path of the xauth program. */
#यदि_परिभाषितम् XAUTH_मार्गः
#परिभाषय मार्गः_XAUTH XAUTH_मार्गः
#यदि_अन्तः /* XAUTH_PATH */

/* derived from XF4/xc/lib/dps/Xlibnet.h */
#यदि_अपरिभाषितम् X_UNIX_मार्गः
#  ifdef __hpux
#    define X_UNIX_मार्गः "/var/spool/sockets/X11/%u"
#  अन्यथा
#    define X_UNIX_मार्गः "/tmp/.X11-unix/X%u"
#  endif
#यदि_अन्तः /* X_UNIX_PATH */
#परिभाषय मार्गः_UNIX_X X_UNIX_मार्गः

#यदि_अपरिभाषितम् _PATH_TTY
# define _PATH_TTY "/dev/tty"
#यदि_अन्तः

/* Macros */

#यदि defined(HAVE_LOGIN_GETCAPBOOL) && defined(HAVE_LOGIN_CAP_H)
# define HAVE_LOGIN_CAP
#यदि_अन्तः

#यदि_अपरिभाषितम् MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
# define MIN(a,b) (((a)<(b))?(a):(b))
#यदि_अन्तः

#यदि_अपरिभाषितम् roundup
# define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#यदि_अन्तः

#यदि_अपरिभाषितम् timersub
#परिभाषय timersub(a, b, परिणाम)					\
   कुरु {								\
      (परिणाम)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
      (परिणाम)->tv_usec = (a)->tv_usec - (b)->tv_usec;		\
      यदि ((परिणाम)->tv_usec < 0) {				\
	 --(परिणाम)->tv_sec;					\
	 (परिणाम)->tv_usec += 1000000;				\
      }								\
   } यावत् (0)
#यदि_अन्तः

#यदि_अपरिभाषितम् timespeccmp
#परिभाषय	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#यदि_अन्तः

#यदि_अपरिभाषितम् TIMEVAL_गन्तव्यम्_TIMESPEC
#परिभाषय	TIMEVAL_गन्तव्यम्_TIMESPEC(tv, ts) {					\
	(ts)->tv_sec = (tv)->tv_sec;					\
	(ts)->tv_nsec = (tv)->tv_usec * 1000;				\
}
#यदि_अन्तः

#यदि_अपरिभाषितम् TIMESPEC_गन्तव्यम्_TIMEVAL
#परिभाषय	TIMESPEC_गन्तव्यम्_TIMEVAL(tv, ts) {					\
	(tv)->tv_sec = (ts)->tv_sec;					\
	(tv)->tv_usec = (ts)->tv_nsec / 1000;				\
}
#यदि_अन्तः

#यदि_अपरिभाषितम् timespeccmp
#परिभाषय timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#यदि_अन्तः

/* Operations on timespecs. */
#यदि_अपरिभाषितम् timespecclear
#परिभाषय	timespecclear(tsp)		(tsp)->tv_sec = (tsp)->tv_nsec = 0
#यदि_अन्तः
#यदि_अपरिभाषितम् timespeccmp
#परिभाषय	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#यदि_अन्तः
#यदि_अपरिभाषितम् timespecadd
#परिभाषय	timespecadd(tsp, usp, vsp)					\
	कुरु {								\
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;	\
		यदि ((vsp)->tv_nsec >= 1000000000L) {			\
			(vsp)->tv_sec++;				\
			(vsp)->tv_nsec -= 1000000000L;			\
		}							\
	} यावत् (0)
#यदि_अन्तः
#यदि_अपरिभाषितम् timespecsub
#परिभाषय	timespecsub(tsp, usp, vsp)					\
	कुरु {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		यदि ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} यावत् (0)
#यदि_अन्तः

#यदि_अपरिभाषितम् __P
# define __P(x) x
#यदि_अन्तः

#यदि !defined(IN6_IS_ADDR_V4MAPPED)
# define IN6_IS_ADDR_V4MAPPED(a) \
	((((u_int32_t *) (a))[0] == 0) && (((u_int32_t *) (a))[1] == 0) && \
	 (((u_int32_t *) (a))[2] == htonl (0xffff)))
#यदि_अन्तः /* !defined(IN6_IS_ADDR_V4MAPPED) */

#यदि !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#यदि_अन्तः /* !defined(__GNUC__) || (__GNUC__ < 2) */

#यदि !defined(HAVE_ATTRIBUTE__SENTINEL__) && !defined(__sentinel__)
# define __sentinel__
#यदि_अन्तः

#यदि !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__bounded__)
# define __bounded__(x, y, z)
#यदि_अन्तः

#यदि !defined(HAVE_ATTRIBUTE__NONNULL__) && !defined(__nonnull__)
# define __nonnull__(x)
#यदि_अन्तः

#यदि !defined(HAVE_ATTRIBUTE__NONSTRING__) && !defined(__nonstring__)
# define __nonstring__
#यदि_अन्तः

#यदि_अपरिभाषितम् OSSH_ALIGNBYTES
#परिभाषय OSSH_ALIGNBYTES	(परिमाण(पूर्णाङ्क) - 1)
#यदि_अन्तः
#यदि_अपरिभाषितम् __CMSG_ALIGN
#परिभाषय	__CMSG_ALIGN(p) (((u_int)(p) + OSSH_ALIGNBYTES) &~ OSSH_ALIGNBYTES)
#यदि_अन्तः

/* Length of the contents of a control message of length len */
#यदि_अपरिभाषितम् CMSG_LEN
#परिभाषय	CMSG_LEN(len)	(__CMSG_ALIGN(परिमाण(संरचना cmsghdr)) + (len))
#यदि_अन्तः

/* Length of the space taken up by a padded control message of length len */
#यदि_अपरिभाषितम् CMSG_SPACE
#परिभाषय	CMSG_SPACE(len)	(__CMSG_ALIGN(परिमाण(संरचना cmsghdr)) + __CMSG_ALIGN(len))
#यदि_अन्तः

/* given pointer to struct cmsghdr, return pointer to data */
#यदि_अपरिभाषितम् CMSG_DATA
#परिभाषय CMSG_DATA(cmsg) ((u_char *)(cmsg) + __CMSG_ALIGN(परिमाण(संरचना cmsghdr)))
#यदि_अन्तः /* CMSG_DATA */

/*
 * RFC 2292 requires to check msg_controllen, in case that the kernel returns
 * an empty list for some reasons.
 */
#यदि_अपरिभाषितम् CMSG_FIRSTHDR
#परिभाषय CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= परिमाण(संरचना cmsghdr) ? \
	 (संरचना cmsghdr *)(mhdr)->msg_control : \
	 (संरचना cmsghdr *)रिक्त)
#यदि_अन्तः /* CMSG_FIRSTHDR */

#यदि defined(HAVE_DECL_OFFSETOF) && HAVE_DECL_OFFSETOF == 0
# define offsetof(type, member) ((आकार_t) &((type *)0)->member)
#यदि_अन्तः

/* Set up BSD-style BYTE_ORDER definition if it isn't there already */
/* XXX: doesn't try to cope with strange byte orders (PDP_ENDIAN) */
#यदि_अपरिभाषितम् BYTE_ORDER
# ifndef LITTLE_ENDIAN
#  define LITTLE_ENDIAN  1234
# endif /* LITTLE_ENDIAN */
# ifndef BIG_ENDIAN
#  define BIG_ENDIAN     4321
# endif /* BIG_ENDIAN */
# ifdef शब्दाः_BIGENDIAN
#  define BYTE_ORDER BIG_ENDIAN
# अन्यथा /* WORDS_BIGENDIAN */
#  define BYTE_ORDER LITTLE_ENDIAN
# endif /* WORDS_BIGENDIAN */
#यदि_अन्तः /* BYTE_ORDER */

#यदि (defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0) || \
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
# ifdef शब्दाः_BIGENDIAN
#  यदि defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) (openssh_swap32(v))
#  endif
#  यदि defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#   define le64toh(v) (openssh_swap64(v))
#  endif
#  यदि defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) (openssh_swap64(v))
#  endif
#  यदि defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) ((uint32_t)v)
#  endif
# अन्यथा
#  यदि defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) ((uint32_t)v)
#  endif
#  यदि defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#    define le64toh(v) ((uint64_t)v)
#  endif
#  यदि defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) ((uint64_t)v)
#  endif
#  यदि defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) (openssh_swap32(v))
#  endif
# endif
#यदि_अन्तः

/* Function replacement / compatibility hacks */

#यदि !defined(HAVE_GETADDRINFO) && (defined(HAVE_OGETADDRINFO) || defined(HAVE_NGETADDRINFO))
# define HAVE_GETADDRINFO
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_GETOPT_OPTRESET
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
#यदि_अन्तः

#यदि defined(BROKEN_GETADDRINFO) && defined(HAVE_GETADDRINFO)
# undef HAVE_GETADDRINFO
#यदि_अन्तः
#यदि defined(BROKEN_GETADDRINFO) && defined(HAVE_FREEADDRINFO)
# undef HAVE_FREEADDRINFO
#यदि_अन्तः
#यदि defined(BROKEN_GETADDRINFO) && defined(HAVE_GAI_STRERROR)
# undef HAVE_GAI_STRERROR
#यदि_अन्तः

#यदि defined(HAVE_GETADDRINFO)
# यदि defined(HAVE_DECL_AI_NUMERICSERV) && HAVE_DECL_AI_NUMERICSERV == 0
#   define AI_NUMERICSERV	0
# endif
#यदि_अन्तः

#यदि defined(BROKEN_UPDWTMPX) && defined(HAVE_UPDWTMPX)
# undef HAVE_UPDWTMPX
#यदि_अन्तः

#यदि defined(BROKEN_SHADOW_EXPIRE) && defined(HAS_SHADOW_EXPIRE)
# undef HAS_SHADOW_EXPIRE
#यदि_अन्तः

#यदि defined(HAVE_OPENLOG_R) && defined(SYSLOG_दत्त_INIT) && \
    defined(SYSLOG_R_SAFE_अन्तर्_SIGHAND)
# define DO_LOG_SAFE_अन्तर्_SIGHAND
#यदि_अन्तः

#यदि !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY)
# define memmove(s1, s2, n) bcopy((s2), (s1), (n))
#यदि_अन्तः /* !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY) */

#यदि_अपरिभाषितम् GETPGRP_VOID
# include <unistd.h>
# define getpgrp() getpgrp(0)
#यदि_अन्तः

#यदि_परिभाषितम् USE_BSM_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#यदि_अन्तः

#यदि_परिभाषितम् USE_LINUX_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#यदि_अन्तः

#यदि !defined(HAVE___func__) && defined(HAVE___FUNCTION__)
#  define __func__ __FUNCTION__
#नोचेद्यदि !defined(HAVE___func__)
#  define __func__ ""
#यदि_अन्तः

#यदि defined(KRB5) && !defined(HEIMDAL)
#  define krb5_get_err_text(context,संहिता) error_सन्देशः(संहिता)
#यदि_अन्तः

/* Maximum number of file descriptors available */
#यदि_परिभाषितम् HAVE_SYSCONF
# define SSH_SYSFDMAX sysconf(_SC_OPEN_MAX)
#अन्यथा
# define SSH_SYSFDMAX 10000
#यदि_अन्तः

#यदि_परिभाषितम् FSID_HAS_VAL
/* encode f_fsid into a 64 bit value  */
#परिभाषय FSID_गन्तव्यम्_ULONG(f) \
	((((u_int64_t)(f).val[0] & 0xffffffffUL) << 32) | \
	    ((f).val[1] & 0xffffffffUL))
#नोचेद्यदि defined(FSID_HAS___VAL)
#परिभाषय FSID_गन्तव्यम्_ULONG(f) \
	((((u_int64_t)(f).__val[0] & 0xffffffffUL) << 32) | \
	    ((f).__val[1] & 0xffffffffUL))
#अन्यथा
# define FSID_गन्तव्यम्_ULONG(f) ((f))
#यदि_अन्तः

#यदि defined(__Lynx__)
 /*
  * LynxOS defines these in param.h which we do not want to include since
  * it will also pull in a bunch of kernel definitions.
  */
# define ALIGNBYTES (परिमाण(पूर्णाङ्क) - 1)
# define ALIGN(p) (((अचिह्नित)p + ALIGNBYTES) & ~ALIGNBYTES)
  /* Missing prototypes on LynxOS */
  पूर्णाङ्क snprintf (वर्ण *, आकार_t, ध्रुव वर्ण *, ...);
  पूर्णाङ्क mkstemp (वर्ण *);
  वर्ण *crypt (ध्रुव वर्ण *, ध्रुव वर्ण *);
  पूर्णाङ्क seteuid (uid_t);
  पूर्णाङ्क setegid (gid_t);
  वर्ण *mkdtemp (वर्ण *);
  पूर्णाङ्क rresvport_af (पूर्णाङ्क *, sa_family_t);
  पूर्णाङ्क innetgr (ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *);
#यदि_अन्तः

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
#यदि_अपरिभाषितम् UTMP_FILE
#  ifdef _PATH_UTMP
#    define UTMP_FILE _PATH_UTMP
#  अन्यथा
#    ifdef CONF_UTMP_FILE
#      define UTMP_FILE CONF_UTMP_FILE
#    endif
#  endif
#यदि_अन्तः
#यदि_अपरिभाषितम् WTMP_FILE
#  ifdef _PATH_WTMP
#    define WTMP_FILE _PATH_WTMP
#  अन्यथा
#    ifdef CONF_WTMP_FILE
#      define WTMP_FILE CONF_WTMP_FILE
#    endif
#  endif
#यदि_अन्तः
/* pick up the user's location for lastlog if given */
#यदि_अपरिभाषितम् LASTLOG_FILE
#  ifdef _PATH_LASTLOG
#    define LASTLOG_FILE _PATH_LASTLOG
#  अन्यथा
#    ifdef CONF_LASTLOG_FILE
#      define LASTLOG_FILE CONF_LASTLOG_FILE
#    endif
#  endif
#यदि_अन्तः

#यदि defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
# define USE_SHADOW
#यदि_अन्तः

/* The login() library function in libutil is first choice */
#यदि defined(HAVE_LOGIN) && !defined(DISABLE_LOGIN)
#  define USE_LOGIN

#अन्यथा
/* Simply select your favourite login types. */
/* Can't do if-else because some systems use several... <sigh> */
#  यदि !defined(DISABLE_UTMPX)
#    define USE_UTMPX
#  endif
#  यदि defined(UTMP_FILE) && !defined(DISABLE_UTMP)
#    define USE_UTMP
#  endif
#  यदि defined(WTMPX_FILE) && !defined(DISABLE_WTMPX)
#    define USE_WTMPX
#  endif
#  यदि defined(WTMP_FILE) && !defined(DISABLE_WTMP)
#    define USE_WTMP
#  endif

#यदि_अन्तः

#यदि_अपरिभाषितम् UT_LINESIZE
# define UT_LINESIZE 8
#यदि_अन्तः

/* I hope that the presence of LASTLOG_FILE is enough to detect this */
#यदि defined(LASTLOG_FILE) && !defined(DISABLE_LASTLOG)
#  define USE_LASTLOG
#यदि_अन्तः

#यदि_परिभाषितम् HAVE_OSF_SIA
# ifdef USE_SHADOW
#  undef USE_SHADOW
# endif
# define CUSTOM_SYS_AUTH_PASSWD 1
#यदि_अन्तः

#यदि defined(HAVE_LIBIAF) && defined(HAVE_समुच्चयः_ID) && !defined(HAVE_SECUREWARE)
# define CUSTOM_SYS_AUTH_PASSWD 1
#यदि_अन्तः
#यदि defined(HAVE_LIBIAF) && defined(HAVE_समुच्चयः_ID) && !defined(BROKEN_LIBIAF)
# define USE_LIBIAF
#यदि_अन्तः

/* HP-UX 11.11 */
#यदि_परिभाषितम् BTMP_FILE
# define मार्गः_BTMP BTMP_FILE
#यदि_अन्तः

#यदि defined(USE_BTMP) && defined(मार्गः_BTMP)
# define CUSTOM_FAILED_LOGIN
#यदि_अन्तः

/** end of login recorder definitions */

#यदि_परिभाषितम् BROKEN_GETGROUPS
# define getgroups(a,b) ((a)==0 && (b)==रिक्त ? NGROUPS_MAX : getgroups((a),(b)))
#यदि_अन्तः

#यदि_अपरिभाषितम् IOV_MAX
# यदि defined(_XOPEN_IOV_MAX)
#  define	IOV_MAX		_XOPEN_IOV_MAX
# elif defined(DEF_IOV_MAX)
#  define	IOV_MAX		DEF_IOV_MAX
# अन्यथा
#  define	IOV_MAX		16
# endif
#यदि_अन्तः

#यदि_अपरिभाषितम् EWOULDBLOCK
# define EWOULDBLOCK EAGAIN
#यदि_अन्तः

#यदि_अपरिभाषितम् INET6_ADDRSTRLEN	/* for non IPv6 machines */
#परिभाषय INET6_ADDRSTRLEN 46
#यदि_अन्तः

#यदि_अपरिभाषितम् SSH_IOBUFSZ
# define SSH_IOBUFSZ 8192
#यदि_अन्तः

/*
 * We want functions in openbsd-compat, if enabled, to override system ones.
 * We no-op out the weak symbol definition rather than remove it to reduce
 * future sync problems.  Some compilers (eg Unixware) do not allow an
 * empty statement, so we use a bogus function declaration.
 */
#परिभाषय DEF_WEAK(x)	शून्य __ssh_compat_weak_##x(शून्य)

/*
 * Platforms that have arc4random_uniform() and not arc4random_stir()
 * shouldn't need the latter.
 */
#यदि defined(HAVE_ARC4RANDOM) && defined(HAVE_ARC4_RANDOM_एकरूपम्) && \
    !defined(HAVE_ARC4RANDOM_STIR)
# define arc4random_stir()
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_VA_COPY
# ifdef HAVE___VA_COPY
#  define va_copy(dest, src) __va_copy(dest, src)
# अन्यथा
#  define va_copy(dest, src) (dest) = (src)
# endif
#यदि_अन्तः

#यदि_अपरिभाषितम् __predict_true
# यदि defined(__GNUC__) && \
     ((__GNUC__ > (2)) || (__GNUC__ == (2) && __GNUC_MINOR__ >= (96)))
#  define __predict_true(घातांकः)     __builtin_expect(((घातांकः) != 0), 1)
#  define __predict_false(घातांकः)    __builtin_expect(((घातांकः) != 0), 0)
# अन्यथा
#  define __predict_true(घातांकः)     ((घातांकः) != 0)
#  define __predict_false(घातांकः)    ((घातांकः) != 0)
# endif /* gcc version */
#यदि_अन्तः /* __predict_true */

/*
 * sntrup761 uses variable length arrays and c99-style declarations after code,
 * so only enable if the compiler supports them.
 */
#यदि defined(VARIABLE_दीर्घता_ARRAYS) && defined(VARIABLE_DECLARATION_AFTER_संहिता)
# define USE_SNTRUP761X25519	1
/* The ML-KEM768 and ML-DSA implementations also uses C89 features */
# define USE_MLKEM768X25519	1
# define USE_MLDSA		1
#यदि_अन्तः

#यदि defined(HAVE_DECL_INFINITY) && HAVE_DECL_INFINITY == 0
# यदि defined(HAVE_DECL___BUILTIN_INFF) && HAVE_DECL___BUILTIN_INFF == 1
#  define INFINITY __builtin_inff()
# endif
#यदि_अन्तः

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
#यदि defined(DISABLE_FD_PASSING) && !defined(HAVE_CYGWIN)
# define SKIP_PRIVDROP 1
#यदि_अन्तः

#यदि_अन्तः /* _DEFINES_H */
