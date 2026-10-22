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

#جے_بنا_تعریف مقرر_کردا_H
#تعریف_کرو مقرر_کردا_H

/* Constants */

#إذا defined(HAVE_DECL_SHUT_RD) && HAVE_DECL_SHUT_RD == 0
تعداد
{
  SHUT_RD = 0,		/* No more receptions.  */
  SHUT_WR,			/* No more transmissions.  */
  SHUT_RDWR			/* No more receptions or transmissions.  */
};
# define SHUT_RD   SHUT_RD
# define SHUT_WR   SHUT_WR
# define SHUT_RDWR SHUT_RDWR
#جے_انت

/*
 * Cygwin doesn't really have a notion of reserved ports.  It is still
 * is useful on the client side so for compatibility it defines as 1024 via
 * netinet/in.h inside an enum.  We * don't actually want that restriction
 * so we want to set that to zero, but we can't do it direct in config.h
 * because it'll cause a conflicting definition the first time we include
 * netinet/in.h.
 */

#جے_تعریف_شدہ HAVE_CYGWIN
#تعریف_کرو IPPORT_RESERVED 0
#جے_انت

/*
 * Definitions for IP type of service (ip_tos)
 */
#ضمن <netinet/ip.h>
#جے_بنا_تعریف IPTOS_LOWDELAY
# define IPTOS_LOWDELAY          0x10
# define IPTOS_THROUGHPUT        0x08
# define IPTOS_RELIABILITY       0x04
# define IPTOS_LOWCOST           0x02
# define IPTOS_MINCOST           IPTOS_LOWCOST
#جے_انت /* IPTOS_LOWDELAY */

/*
 * Definitions for DiffServ Codepoints as per RFCs 2474, 3246, 4594 & 8622.
 * These are the 6 most significant bits as they appear on the wire, so the
 * two least significant bits must be zero.
 */
#جے_بنا_تعریف IPTOS_DSCP_AF11
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
#جے_انت /* IPTOS_DSCP_AF11 */
#جے_بنا_تعریف IPTOS_DSCP_CS0
# define	IPTOS_DSCP_CS0		0x00
# define	IPTOS_DSCP_CS1		0x20
# define	IPTOS_DSCP_CS2		0x40
# define	IPTOS_DSCP_CS3		0x60
# define	IPTOS_DSCP_CS4		0x80
# define	IPTOS_DSCP_CS5		0xa0
# define	IPTOS_DSCP_CS6		0xc0
# define	IPTOS_DSCP_CS7		0xe0
#جے_انت /* IPTOS_DSCP_CS0 */
#جے_بنا_تعریف IPTOS_DSCP_VA
# define	IPTOS_DSCP_VA		0xb0
#جے_انت /* IPTOS_DSCP_VA */
#جے_بنا_تعریف IPTOS_DSCP_EF
# define	IPTOS_DSCP_EF		0xb8
#جے_انت /* IPTOS_DSCP_EF */
#جے_بنا_تعریف IPTOS_DSCP_LE
# define	IPTOS_DSCP_LE		0x04
#جے_انت /* IPTOS_DSCP_LE */
#جے_بنا_تعریف IPTOS_PREC_CRITIC_ECP
# define IPTOS_PREC_CRITIC_ECP		0xa0
#جے_انت
#جے_بنا_تعریف IPTOS_PREC_INTERNETCONTROL
# define IPTOS_PREC_INTERNETCONTROL	0xc0
#جے_انت
#جے_بنا_تعریف IPTOS_PREC_NETCONTROL
# define IPTOS_PREC_NETCONTROL		0xe0
#جے_انت

#جے_بنا_تعریف PATH_MAX
# ifdef _POSIX_PATH_MAX
# define PATH_MAX _POSIX_PATH_MAX
# endif
#جے_انت

#جے_بنا_تعریف MAXPATHLEN
# ifdef PATH_MAX
#  define MAXPATHLEN PATH_MAX
# وإلا /* PATH_MAX */
#  define MAXPATHLEN 64
# endif /* PATH_MAX */
#جے_انت /* MAXPATHLEN */

#جے_بنا_تعریف HOST_NAME_MAX
# include "netdb.h" /* for MAXHOSTNAMELEN */
# إذا defined(_POSIX_HOST_NAME_MAX)
#  define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# elif defined(MAXHOSTNAMELEN)
#  define HOST_NAME_MAX MAXHOSTNAMELEN
# وإلا
#  define HOST_NAME_MAX	255
# endif
#جے_انت /* HOST_NAME_MAX */

#إذا defined(HAVE_DECL_MAXSYMLINKS) && HAVE_DECL_MAXSYMLINKS == 0
# define MAXSYMLINKS 5
#جے_انت

#جے_بنا_تعریف STDIN_FILENO
# define STDIN_FILENO    0
#جے_انت
#جے_بنا_تعریف STDOUT_FILENO
# define STDOUT_FILENO   1
#جے_انت
#جے_بنا_تعریف STDERR_FILENO
# define STDERR_FILENO   2
#جے_انت

#جے_بنا_تعریف NGROUPS_MAX	/* Disable groupaccess if NGROUP_MAX is not set */
#جے_تعریف_شدہ NGROUPS
#تعریف_کرو NGROUPS_MAX NGROUPS
#وإلا
#تعریف_کرو NGROUPS_MAX 0
#جے_انت
#جے_انت

#إذا defined(HAVE_DECL_O_NONBLOCK) && HAVE_DECL_O_NONBLOCK == 0
# define O_NONBLOCK      00004	/* Non Blocking Open */
#جے_انت

#جے_بنا_تعریف S_IFSOCK
# define S_IFSOCK 0
#جے_انت /* S_IFSOCK */

#جے_بنا_تعریف S_ISDIR
# define S_ISDIR(منوال)	(((منوال) & (_S_IFMT)) == (_S_IFDIR))
#جے_انت /* S_ISDIR */

#جے_بنا_تعریف S_ISREG
# define S_ISREG(منوال)	(((منوال) & (_S_IFMT)) == (_S_IFREG))
#جے_انت /* S_ISREG */

#جے_بنا_تعریف S_ISLNK
# define S_ISLNK(منوال)	(((منوال) & S_IFMT) == S_IFLNK)
#جے_انت /* S_ISLNK */

#جے_بنا_تعریف S_IXUSR
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
#جے_انت /* S_IXUSR */

#إذا !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
#تعریف_کرو MAP_ANON MAP_ANONYMOUS
#جے_انت

#جے_بنا_تعریف MAP_FAILED
# define MAP_FAILED ((فراغ *)-1)
#جے_انت

/*
SCO Open Server 3 has INADDR_LOOPBACK defined in rpc/rpc.h but
including rpc/rpc.h breaks Solaris 6
*/
#جے_بنا_تعریف INADDR_LOOPBACK
#تعریف_کرو INADDR_LOOPBACK ((u_long)0x7f000001)
#جے_انت

/* Types */

/* If sys/types.h does not supply intXX_t, supply them ourselves */
/* (or die trying) */

#جے_بنا_تعریف HAVE_U_INT
تعريفنوع بنانشانی چھوٹا u_short;
تعريفنوع بنانشانی صحيح u_int;
تعريفنوع بنانشانی لما u_long;
#جے_انت

#جے_بنا_تعریف HAVE_INTXX_T
تعريفنوع نشانیوالا حرف int8_t;
# إذا (SIZEOF_SHORT_INT == 2)
تعريفنوع چھوٹا صحيح int16_t;
# وإلا
#   error "16 bit int type not found."
# endif
# إذا (SIZEOF_INT == 4)
تعريفنوع صحيح int32_t;
# وإلا
#   error "32 bit int type not found."
# endif
#جے_انت

/* If sys/types.h does not supply u_intXX_t, supply them ourselves */
#جے_بنا_تعریف HAVE_U_INTXX_T
# ifdef HAVE_UINTXX_T
تعريفنوع uint8_t u_int8_t;
تعريفنوع uint16_t u_int16_t;
تعريفنوع uint32_t u_int32_t;
# define HAVE_U_INTXX_T 1
# وإلا
تعريفنوع بنانشانی حرف u_int8_t;
#  إذا (SIZEOF_SHORT_INT == 2)
تعريفنوع بنانشانی چھوٹا صحيح u_int16_t;
#  وإلا
#    error "16 bit int type not found."
#  endif
#  إذا (SIZEOF_INT == 4)
تعريفنوع بنانشانی صحيح u_int32_t;
#  وإلا
#    error "32 bit int type not found."
#  endif
# endif
#تعریف_کرو __BIT_TYPES_DEFINED__
#جے_انت

#إذا !defined(LLONG_MIN) && defined(LONG_LONG_MIN)
#تعریف_کرو LLONG_MIN LONG_LONG_MIN
#جے_انت
#إذا !defined(LLONG_MAX) && defined(LONG_LONG_MAX)
#تعریف_کرو LLONG_MAX LONG_LONG_MAX
#جے_انت

#جے_بنا_تعریف UINT32_MAX
# إذا defined(HAVE_DECL_UINT32_MAX) && (HAVE_DECL_UINT32_MAX == 0)
#  إذا (SIZEOF_INT == 4)
#    define UINT32_MAX	UINT_MAX
#  endif
# endif
#جے_انت

/* 64-bit types */
#جے_بنا_تعریف HAVE_INT64_T
# إذا (SIZEOF_LONG_INT == 8)
تعريفنوع لما صحيح int64_t;
# وإلا
#  إذا (SIZEOF_LONG_LONG_INT == 8)
تعريفنوع لما لما صحيح int64_t;
#  endif
# endif
#جے_انت
#جے_بنا_تعریف HAVE_U_INT64_T
# إذا (SIZEOF_LONG_INT == 8)
تعريفنوع بنانشانی لما صحيح u_int64_t;
# وإلا
#  إذا (SIZEOF_LONG_LONG_INT == 8)
تعريفنوع بنانشانی لما لما صحيح u_int64_t;
#  endif
# endif
#جے_انت

#جے_بنا_تعریف HAVE_UINTXX_T
تعريفنوع u_int8_t uint8_t;
تعريفنوع u_int16_t uint16_t;
تعريفنوع u_int32_t uint32_t;
تعريفنوع u_int64_t uint64_t;
#جے_انت

#جے_بنا_تعریف HAVE_INTMAX_T
تعريفنوع لما لما intmax_t;
#جے_انت

#جے_بنا_تعریف HAVE_UINTMAX_T
تعريفنوع بنانشانی لما لما uintmax_t;
#جے_انت

#إذا SIZEOF_ویلا_T == SIZEOF_LONG_LONG_INT
# define SSH_ویلا_T_MAX LLONG_MAX
#وإلا
# define SSH_ویلا_T_MAX ودھ_توں_ودھ_عدد
#جے_انت

#جے_بنا_تعریف HAVE_U_CHAR
تعريفنوع بنانشانی حرف u_char;
# define HAVE_U_CHAR
#جے_انت /* HAVE_U_CHAR */

#جے_بنا_تعریف ULLONG_MAX
# define ULLONG_MAX ((بنانشانی لما لما)-1)
#جے_انت

#جے_بنا_تعریف ناپ_T_MAX
#تعریف_کرو ناپ_T_MAX ULONG_MAX
#جے_انت /* SIZE_T_MAX */

#جے_بنا_تعریف HAVE_ناپ_T
تعريفنوع بنانشانی صحيح ناپ_t;
# define HAVE_ناپ_T
# define ناپ_T_MAX UINT_MAX
#جے_انت /* HAVE_SIZE_T */

#جے_بنا_تعریف SIZE_MAX
#تعریف_کرو SIZE_MAX ناپ_T_MAX
#جے_انت

#جے_بنا_تعریف INT32_MAX
# إذا (SIZEOF_INT == 4)
#  define INT32_MAX ودھ_توں_ودھ_عدد
# elif (SIZEOF_LONG == 4)
#  define INT32_MAX LONG_MAX
# وإلا
#  error "need INT32_MAX"
# endif
#جے_انت

#جے_بنا_تعریف INT64_MAX
# إذا (SIZEOF_INT == 8)
#  define INT64_MAX ودھ_توں_ودھ_عدد
# elif (SIZEOF_LONG == 8)
#  define INT64_MAX LONG_MAX
# elif (SIZEOF_LONG_LONG_INT == 8)
#  define INT64_MAX LLONG_MAX
# وإلا
#  error "need INT64_MAX"
# endif
#جے_انت

#جے_بنا_تعریف HAVE_SSIZE_T
تعريفنوع صحيح ssize_t;
#تعریف_کرو SSIZE_MAX ودھ_توں_ودھ_عدد
# define HAVE_SSIZE_T
#جے_انت /* HAVE_SSIZE_T */

#جے_بنا_تعریف HAVE_CLOCK_T
تعريفنوع لما clock_t;
# define HAVE_CLOCK_T
#جے_انت /* HAVE_CLOCK_T */

#جے_بنا_تعریف HAVE_SA_FAMILY_T
تعريفنوع صحيح sa_family_t;
# define HAVE_SA_FAMILY_T
#جے_انت /* HAVE_SA_FAMILY_T */

#جے_بنا_تعریف HAVE_PID_T
تعريفنوع صحيح pid_t;
# define HAVE_PID_T
#جے_انت /* HAVE_PID_T */

#جے_بنا_تعریف HAVE_SIG_ATOMIC_T
تعريفنوع صحيح sig_atomic_t;
# define HAVE_SIG_ATOMIC_T
#جے_انت /* HAVE_SIG_ATOMIC_T */

#جے_بنا_تعریف HAVE_منوال_T
تعريفنوع صحيح منوال_t;
# define HAVE_منوال_T
#جے_انت /* HAVE_MODE_T */

#إذا !defined(HAVE_SS_FAMILY_وچ_SS) && defined(HAVE_SS_FAMILY_وچ_SS_2)
# define ss_family __ss_family
#جے_انت /* !defined(HAVE_SS_FAMILY_IN_SS) && defined(HAVE_SA_FAMILY_IN_SS) */

#جے_بنا_تعریف HAVE_SYS_UN_H
بنية	sockaddr_un {
	چھوٹا	sun_family;		/* AF_UNIX */
	حرف	sun_رستہ[108];		/* path name (gag) */
};
#جے_انت /* HAVE_SYS_UN_H */

#جے_بنا_تعریف HAVE_وچ_ADDR_T
تعريفنوع u_int32_t	in_addr_t;
#جے_انت
#جے_بنا_تعریف HAVE_وچ_پورٹ_T
تعريفنوع u_int16_t	in_port_t;
#جے_انت

#إذا defined(BROKEN_SYS_TERMIO_H) && !defined(_STRUCT_WINSIZE)
#تعریف_کرو _STRUCT_WINSIZE
بنية winsize {
      بنانشانی چھوٹا ws_صف;          /* rows, in characters */
      بنانشانی چھوٹا ws_خانہ;          /* columns, in character */
      بنانشانی چھوٹا ws_xpixel;       /* horizontal size, pixels */
      بنانشانی چھوٹا ws_ypixel;       /* vertical size, pixels */
};
#جے_انت

/* bits needed for select that may not be in the system headers */
#جے_بنا_تعریف HAVE_FD_نقاب
 تعريفنوع بنانشانی لما صحيح	fd_نقاب;
#جے_انت

#إذا defined(HAVE_DECL_NFDBITS) && HAVE_DECL_NFDBITS == 0
# define	NFDBITS (8 * حجم(بنانشانی لما))
#جے_انت

#إذا defined(HAVE_DECL_HOWMANY) && HAVE_DECL_HOWMANY == 0
# define howmany(x,y)	(((x)+((y)-1))/(y))
#جے_انت

/* Paths */

#جے_بنا_تعریف _PATH_BSHELL
# define _PATH_BSHELL "/bin/sh"
#جے_انت

#جے_تعریف_شدہ USER_رستہ
# ifdef _PATH_STDPATH
#  undef _PATH_STDPATH
# endif
# define _PATH_STDPATH USER_رستہ
#جے_انت

#جے_بنا_تعریف _PATH_STDPATH
# define _PATH_STDPATH "/usr/bin:/bin:/usr/sbin:/sbin"
#جے_انت

#جے_بنا_تعریف SUPERUSER_رستہ
# define SUPERUSER_رستہ	_PATH_STDPATH
#جے_انت

#جے_بنا_تعریف _PATH_DEVNULL
# define _PATH_DEVNULL "/dev/null"
#جے_انت

/* user may have set a different path */
#إذا defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY)
# undef _PATH_MAILDIR
#جے_انت /* defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY) */

#جے_تعریف_شدہ MAIL_DIRECTORY
# define _PATH_MAILDIR MAIL_DIRECTORY
#جے_انت

#جے_بنا_تعریف _PATH_NOLOGIN
# define _PATH_NOLOGIN "/etc/nologin"
#جے_انت

/* Define this to be the path of the xauth program. */
#جے_تعریف_شدہ XAUTH_رستہ
#تعریف_کرو رستہ_XAUTH XAUTH_رستہ
#جے_انت /* XAUTH_PATH */

/* derived from XF4/xc/lib/dps/Xlibnet.h */
#جے_بنا_تعریف X_UNIX_رستہ
#  ifdef __hpux
#    define X_UNIX_رستہ "/var/spool/sockets/X11/%u"
#  وإلا
#    define X_UNIX_رستہ "/tmp/.X11-unix/X%u"
#  endif
#جے_انت /* X_UNIX_PATH */
#تعریف_کرو رستہ_UNIX_X X_UNIX_رستہ

#جے_بنا_تعریف _PATH_TTY
# define _PATH_TTY "/dev/tty"
#جے_انت

/* Macros */

#إذا defined(HAVE_LOGIN_GETCAPBOOL) && defined(HAVE_LOGIN_CAP_H)
# define HAVE_LOGIN_CAP
#جے_انت

#جے_بنا_تعریف MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
# define MIN(a,b) (((a)<(b))?(a):(b))
#جے_انت

#جے_بنا_تعریف roundup
# define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#جے_انت

#جے_بنا_تعریف timersub
#تعریف_کرو timersub(a, b, نتیجہ)					\
   افعل {								\
      (نتیجہ)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
      (نتیجہ)->tv_usec = (a)->tv_usec - (b)->tv_usec;		\
      إذا ((نتیجہ)->tv_usec < 0) {				\
	 --(نتیجہ)->tv_sec;					\
	 (نتیجہ)->tv_usec += 1000000;				\
      }								\
   } طالما (0)
#جے_انت

#جے_بنا_تعریف timespeccmp
#تعریف_کرو	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#جے_انت

#جے_بنا_تعریف TIMEVAL_منزل_TIMESPEC
#تعریف_کرو	TIMEVAL_منزل_TIMESPEC(tv, ts) {					\
	(ts)->tv_sec = (tv)->tv_sec;					\
	(ts)->tv_nsec = (tv)->tv_usec * 1000;				\
}
#جے_انت

#جے_بنا_تعریف TIMESPEC_منزل_TIMEVAL
#تعریف_کرو	TIMESPEC_منزل_TIMEVAL(tv, ts) {					\
	(tv)->tv_sec = (ts)->tv_sec;					\
	(tv)->tv_usec = (ts)->tv_nsec / 1000;				\
}
#جے_انت

#جے_بنا_تعریف timespeccmp
#تعریف_کرو timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#جے_انت

/* Operations on timespecs. */
#جے_بنا_تعریف timespecclear
#تعریف_کرو	timespecclear(tsp)		(tsp)->tv_sec = (tsp)->tv_nsec = 0
#جے_انت
#جے_بنا_تعریف timespeccmp
#تعریف_کرو	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#جے_انت
#جے_بنا_تعریف timespecadd
#تعریف_کرو	timespecadd(tsp, usp, vsp)					\
	افعل {								\
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;	\
		إذا ((vsp)->tv_nsec >= 1000000000L) {			\
			(vsp)->tv_sec++;				\
			(vsp)->tv_nsec -= 1000000000L;			\
		}							\
	} طالما (0)
#جے_انت
#جے_بنا_تعریف timespecsub
#تعریف_کرو	timespecsub(tsp, usp, vsp)					\
	افعل {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		إذا ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} طالما (0)
#جے_انت

#جے_بنا_تعریف __P
# define __P(x) x
#جے_انت

#إذا !defined(IN6_IS_ADDR_V4MAPPED)
# define IN6_IS_ADDR_V4MAPPED(a) \
	((((u_int32_t *) (a))[0] == 0) && (((u_int32_t *) (a))[1] == 0) && \
	 (((u_int32_t *) (a))[2] == htonl (0xffff)))
#جے_انت /* !defined(IN6_IS_ADDR_V4MAPPED) */

#إذا !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#جے_انت /* !defined(__GNUC__) || (__GNUC__ < 2) */

#إذا !defined(HAVE_ATTRIBUTE__SENTINEL__) && !defined(__sentinel__)
# define __sentinel__
#جے_انت

#إذا !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__bounded__)
# define __bounded__(x, y, z)
#جے_انت

#إذا !defined(HAVE_ATTRIBUTE__NONNULL__) && !defined(__nonnull__)
# define __nonnull__(x)
#جے_انت

#إذا !defined(HAVE_ATTRIBUTE__NONSTRING__) && !defined(__nonstring__)
# define __nonstring__
#جے_انت

#جے_بنا_تعریف OSSH_ALIGNBYTES
#تعریف_کرو OSSH_ALIGNBYTES	(حجم(صحيح) - 1)
#جے_انت
#جے_بنا_تعریف __CMSG_ALIGN
#تعریف_کرو	__CMSG_ALIGN(p) (((u_int)(p) + OSSH_ALIGNBYTES) &~ OSSH_ALIGNBYTES)
#جے_انت

/* Length of the contents of a control message of length len */
#جے_بنا_تعریف CMSG_LEN
#تعریف_کرو	CMSG_LEN(len)	(__CMSG_ALIGN(حجم(بنية cmsghdr)) + (len))
#جے_انت

/* Length of the space taken up by a padded control message of length len */
#جے_بنا_تعریف CMSG_SPACE
#تعریف_کرو	CMSG_SPACE(len)	(__CMSG_ALIGN(حجم(بنية cmsghdr)) + __CMSG_ALIGN(len))
#جے_انت

/* given pointer to struct cmsghdr, return pointer to data */
#جے_بنا_تعریف CMSG_DATA
#تعریف_کرو CMSG_DATA(cmsg) ((u_char *)(cmsg) + __CMSG_ALIGN(حجم(بنية cmsghdr)))
#جے_انت /* CMSG_DATA */

/*
 * RFC 2292 requires to check msg_controllen, in case that the kernel returns
 * an empty list for some reasons.
 */
#جے_بنا_تعریف CMSG_FIRSTHDR
#تعریف_کرو CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= حجم(بنية cmsghdr) ? \
	 (بنية cmsghdr *)(mhdr)->msg_control : \
	 (بنية cmsghdr *)عدم)
#جے_انت /* CMSG_FIRSTHDR */

#إذا defined(HAVE_DECL_OFFSETOF) && HAVE_DECL_OFFSETOF == 0
# define offsetof(type, member) ((ناپ_t) &((type *)0)->member)
#جے_انت

/* Set up BSD-style BYTE_ORDER definition if it isn't there already */
/* XXX: doesn't try to cope with strange byte orders (PDP_ENDIAN) */
#جے_بنا_تعریف BYTE_ORDER
# ifndef LITTLE_ENDIAN
#  define LITTLE_ENDIAN  1234
# endif /* LITTLE_ENDIAN */
# ifndef BIG_ENDIAN
#  define BIG_ENDIAN     4321
# endif /* BIG_ENDIAN */
# ifdef الفاظ_BIGENDIAN
#  define BYTE_ORDER BIG_ENDIAN
# وإلا /* WORDS_BIGENDIAN */
#  define BYTE_ORDER LITTLE_ENDIAN
# endif /* WORDS_BIGENDIAN */
#جے_انت /* BYTE_ORDER */

#إذا (defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0) || \
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
# ifdef الفاظ_BIGENDIAN
#  إذا defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) (openssh_swap32(v))
#  endif
#  إذا defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#   define le64toh(v) (openssh_swap64(v))
#  endif
#  إذا defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) (openssh_swap64(v))
#  endif
#  إذا defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) ((uint32_t)v)
#  endif
# وإلا
#  إذا defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) ((uint32_t)v)
#  endif
#  إذا defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#    define le64toh(v) ((uint64_t)v)
#  endif
#  إذا defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) ((uint64_t)v)
#  endif
#  إذا defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) (openssh_swap32(v))
#  endif
# endif
#جے_انت

/* Function replacement / compatibility hacks */

#إذا !defined(HAVE_GETADDRINFO) && (defined(HAVE_OGETADDRINFO) || defined(HAVE_NGETADDRINFO))
# define HAVE_GETADDRINFO
#جے_انت

#جے_بنا_تعریف HAVE_GETOPT_OPTRESET
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
#جے_انت

#إذا defined(BROKEN_GETADDRINFO) && defined(HAVE_GETADDRINFO)
# undef HAVE_GETADDRINFO
#جے_انت
#إذا defined(BROKEN_GETADDRINFO) && defined(HAVE_FREEADDRINFO)
# undef HAVE_FREEADDRINFO
#جے_انت
#إذا defined(BROKEN_GETADDRINFO) && defined(HAVE_GAI_STRERROR)
# undef HAVE_GAI_STRERROR
#جے_انت

#إذا defined(HAVE_GETADDRINFO)
# إذا defined(HAVE_DECL_AI_NUMERICSERV) && HAVE_DECL_AI_NUMERICSERV == 0
#   define AI_NUMERICSERV	0
# endif
#جے_انت

#إذا defined(BROKEN_UPDWTMPX) && defined(HAVE_UPDWTMPX)
# undef HAVE_UPDWTMPX
#جے_انت

#إذا defined(BROKEN_SHADOW_EXPIRE) && defined(HAS_SHADOW_EXPIRE)
# undef HAS_SHADOW_EXPIRE
#جے_انت

#إذا defined(HAVE_OPENLOG_R) && defined(SYSLOG_انکڑے_INIT) && \
    defined(SYSLOG_R_محفوظ_وچ_SIGHAND)
# define DO_LOG_محفوظ_وچ_SIGHAND
#جے_انت

#إذا !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY)
# define memmove(s1, s2, n) bcopy((s2), (s1), (n))
#جے_انت /* !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY) */

#جے_بنا_تعریف GETPGRP_VOID
# include <unistd.h>
# define getpgrp() getpgrp(0)
#جے_انت

#جے_تعریف_شدہ USE_BSM_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#جے_انت

#جے_تعریف_شدہ USE_LINUX_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#جے_انت

#إذا !defined(HAVE___func__) && defined(HAVE___FUNCTION__)
#  define __func__ __FUNCTION__
#وإلاإذا !defined(HAVE___func__)
#  define __func__ ""
#جے_انت

#إذا defined(KRB5) && !defined(HEIMDAL)
#  define krb5_get_err_متن(context,کوڈ) error_سنیہا(کوڈ)
#جے_انت

/* Maximum number of file descriptors available */
#جے_تعریف_شدہ HAVE_SYSCONF
# define SSH_SYSFDMAX sysconf(_SC_OPEN_MAX)
#وإلا
# define SSH_SYSFDMAX 10000
#جے_انت

#جے_تعریف_شدہ FSID_HAS_VAL
/* encode f_fsid into a 64 bit value  */
#تعریف_کرو FSID_منزل_ULONG(f) \
	((((u_int64_t)(f).val[0] & 0xffffffffUL) << 32) | \
	    ((f).val[1] & 0xffffffffUL))
#وإلاإذا defined(FSID_HAS___VAL)
#تعریف_کرو FSID_منزل_ULONG(f) \
	((((u_int64_t)(f).__val[0] & 0xffffffffUL) << 32) | \
	    ((f).__val[1] & 0xffffffffUL))
#وإلا
# define FSID_منزل_ULONG(f) ((f))
#جے_انت

#إذا defined(__Lynx__)
 /*
  * LynxOS defines these in param.h which we do not want to include since
  * it will also pull in a bunch of kernel definitions.
  */
# define ALIGNBYTES (حجم(صحيح) - 1)
# define ALIGN(p) (((بنانشانی)p + ALIGNBYTES) & ~ALIGNBYTES)
  /* Missing prototypes on LynxOS */
  صحيح snprintf (حرف *, ناپ_t, ثابت حرف *, ...);
  صحيح mkstemp (حرف *);
  حرف *crypt (ثابت حرف *, ثابت حرف *);
  صحيح seteuid (uid_t);
  صحيح setegid (gid_t);
  حرف *mkdtemp (حرف *);
  صحيح rresvport_af (صحيح *, sa_family_t);
  صحيح innetgr (ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);
#جے_انت

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
#جے_بنا_تعریف UTMP_FILE
#  ifdef _PATH_UTMP
#    define UTMP_FILE _PATH_UTMP
#  وإلا
#    ifdef CONF_UTMP_FILE
#      define UTMP_FILE CONF_UTMP_FILE
#    endif
#  endif
#جے_انت
#جے_بنا_تعریف WTMP_FILE
#  ifdef _PATH_WTMP
#    define WTMP_FILE _PATH_WTMP
#  وإلا
#    ifdef CONF_WTMP_FILE
#      define WTMP_FILE CONF_WTMP_FILE
#    endif
#  endif
#جے_انت
/* pick up the user's location for lastlog if given */
#جے_بنا_تعریف LASTLOG_FILE
#  ifdef _PATH_LASTLOG
#    define LASTLOG_FILE _PATH_LASTLOG
#  وإلا
#    ifdef CONF_LASTLOG_FILE
#      define LASTLOG_FILE CONF_LASTLOG_FILE
#    endif
#  endif
#جے_انت

#إذا defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
# define USE_SHADOW
#جے_انت

/* The login() library function in libutil is first choice */
#إذا defined(HAVE_LOGIN) && !defined(DISABLE_LOGIN)
#  define USE_LOGIN

#وإلا
/* Simply select your favourite login types. */
/* Can't do if-else because some systems use several... <sigh> */
#  إذا !defined(DISABLE_UTMPX)
#    define USE_UTMPX
#  endif
#  إذا defined(UTMP_FILE) && !defined(DISABLE_UTMP)
#    define USE_UTMP
#  endif
#  إذا defined(WTMPX_FILE) && !defined(DISABLE_WTMPX)
#    define USE_WTMPX
#  endif
#  إذا defined(WTMP_FILE) && !defined(DISABLE_WTMP)
#    define USE_WTMP
#  endif

#جے_انت

#جے_بنا_تعریف UT_LINESIZE
# define UT_LINESIZE 8
#جے_انت

/* I hope that the presence of LASTLOG_FILE is enough to detect this */
#إذا defined(LASTLOG_FILE) && !defined(DISABLE_LASTLOG)
#  define USE_LASTLOG
#جے_انت

#جے_تعریف_شدہ HAVE_OSF_SIA
# ifdef USE_SHADOW
#  undef USE_SHADOW
# endif
# define CUSTOM_SYS_AUTH_PASSWD 1
#جے_انت

#إذا defined(HAVE_LIBIAF) && defined(HAVE_سیٹ_ID) && !defined(HAVE_SECUREWARE)
# define CUSTOM_SYS_AUTH_PASSWD 1
#جے_انت
#إذا defined(HAVE_LIBIAF) && defined(HAVE_سیٹ_ID) && !defined(BROKEN_LIBIAF)
# define USE_LIBIAF
#جے_انت

/* HP-UX 11.11 */
#جے_تعریف_شدہ BTMP_FILE
# define رستہ_BTMP BTMP_FILE
#جے_انت

#إذا defined(USE_BTMP) && defined(رستہ_BTMP)
# define CUSTOM_FAILED_LOGIN
#جے_انت

/** end of login recorder definitions */

#جے_تعریف_شدہ BROKEN_GETGROUPS
# define getgroups(a,b) ((a)==0 && (b)==عدم ? NGROUPS_MAX : getgroups((a),(b)))
#جے_انت

#جے_بنا_تعریف IOV_MAX
# إذا defined(_XOPEN_IOV_MAX)
#  define	IOV_MAX		_XOPEN_IOV_MAX
# elif defined(DEF_IOV_MAX)
#  define	IOV_MAX		DEF_IOV_MAX
# وإلا
#  define	IOV_MAX		16
# endif
#جے_انت

#جے_بنا_تعریف EWOULDBLOCK
# define EWOULDBLOCK EAGAIN
#جے_انت

#جے_بنا_تعریف INET6_ADDRSTRLEN	/* for non IPv6 machines */
#تعریف_کرو INET6_ADDRSTRLEN 46
#جے_انت

#جے_بنا_تعریف SSH_IOBUFSZ
# define SSH_IOBUFSZ 8192
#جے_انت

/*
 * We want functions in openbsd-compat, if enabled, to override system ones.
 * We no-op out the weak symbol definition rather than remove it to reduce
 * future sync problems.  Some compilers (eg Unixware) do not allow an
 * empty statement, so we use a bogus function declaration.
 */
#تعریف_کرو DEF_WEAK(x)	فراغ __ssh_compat_weak_##x(فراغ)

/*
 * Platforms that have arc4random_uniform() and not arc4random_stir()
 * shouldn't need the latter.
 */
#إذا defined(HAVE_ARC4RANDOM) && defined(HAVE_ARC4_RANDOM_اکسار) && \
    !defined(HAVE_ARC4RANDOM_STIR)
# define arc4random_stir()
#جے_انت

#جے_بنا_تعریف HAVE_VA_COPY
# ifdef HAVE___VA_COPY
#  define va_copy(dest, src) __va_copy(dest, src)
# وإلا
#  define va_copy(dest, src) (dest) = (src)
# endif
#جے_انت

#جے_بنا_تعریف __predict_true
# إذا defined(__GNUC__) && \
     ((__GNUC__ > (2)) || (__GNUC__ == (2) && __GNUC_MINOR__ >= (96)))
#  define __predict_true(قوت_نما)     __builtin_expect(((قوت_نما) != 0), 1)
#  define __predict_false(قوت_نما)    __builtin_expect(((قوت_نما) != 0), 0)
# وإلا
#  define __predict_true(قوت_نما)     ((قوت_نما) != 0)
#  define __predict_false(قوت_نما)    ((قوت_نما) != 0)
# endif /* gcc version */
#جے_انت /* __predict_true */

/*
 * sntrup761 uses variable length arrays and c99-style declarations after code,
 * so only enable if the compiler supports them.
 */
#إذا defined(VARIABLE_لمائی_ARRAYS) && defined(VARIABLE_DECLARATION_AFTER_کوڈ)
# define USE_SNTRUP761X25519	1
/* The ML-KEM768 and ML-DSA implementations also uses C89 features */
# define USE_MLKEM768X25519	1
# define USE_MLDSA		1
#جے_انت

#إذا defined(HAVE_DECL_INFINITY) && HAVE_DECL_INFINITY == 0
# إذا defined(HAVE_DECL___BUILTIN_INFF) && HAVE_DECL___BUILTIN_INFF == 1
#  define INFINITY __builtin_inff()
# endif
#جے_انت

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
#إذا defined(DISABLE_FD_PASSING) && !defined(HAVE_CYGWIN)
# define SKIP_PRIVDROP 1
#جے_انت

#جے_انت /* _DEFINES_H */
