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

#اگر_غیر_تعریف_شدہ متعین_کرتا_H
#تعریف_کرو متعین_کرتا_H

/* Constants */

#اگر defined(HAVE_DECL_SHUT_RD) && HAVE_DECL_SHUT_RD == 0
شمار
{
  SHUT_RD = 0,		/* No more receptions.  */
  SHUT_WR,			/* No more transmissions.  */
  SHUT_RDWR			/* No more receptions or transmissions.  */
};
# define SHUT_RD   SHUT_RD
# define SHUT_WR   SHUT_WR
# define SHUT_RDWR SHUT_RDWR
#اگر_ختم

/*
 * Cygwin doesn't really have a notion of reserved ports.  It is still
 * is useful on the client side so for compatibility it defines as 1024 via
 * netinet/in.h inside an enum.  We * don't actually want that restriction
 * so we want to set that to zero, but we can't do it direct in config.h
 * because it'll cause a conflicting definition the first time we include
 * netinet/in.h.
 */

#اگر_تعریف_شدہ HAVE_CYGWIN
#تعریف_کرو IPPORT_RESERVED 0
#اگر_ختم

/*
 * Definitions for IP type of service (ip_tos)
 */
#شامل <netinet/ip.h>
#اگر_غیر_تعریف_شدہ IPTOS_LOWDELAY
# define IPTOS_LOWDELAY          0x10
# define IPTOS_THROUGHPUT        0x08
# define IPTOS_RELIABILITY       0x04
# define IPTOS_LOWCOST           0x02
# define IPTOS_MINCOST           IPTOS_LOWCOST
#اگر_ختم /* IPTOS_LOWDELAY */

/*
 * Definitions for DiffServ Codepoints as per RFCs 2474, 3246, 4594 & 8622.
 * These are the 6 most significant bits as they appear on the wire, so the
 * two least significant bits must be zero.
 */
#اگر_غیر_تعریف_شدہ IPTOS_DSCP_AF11
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
#اگر_ختم /* IPTOS_DSCP_AF11 */
#اگر_غیر_تعریف_شدہ IPTOS_DSCP_CS0
# define	IPTOS_DSCP_CS0		0x00
# define	IPTOS_DSCP_CS1		0x20
# define	IPTOS_DSCP_CS2		0x40
# define	IPTOS_DSCP_CS3		0x60
# define	IPTOS_DSCP_CS4		0x80
# define	IPTOS_DSCP_CS5		0xa0
# define	IPTOS_DSCP_CS6		0xc0
# define	IPTOS_DSCP_CS7		0xe0
#اگر_ختم /* IPTOS_DSCP_CS0 */
#اگر_غیر_تعریف_شدہ IPTOS_DSCP_VA
# define	IPTOS_DSCP_VA		0xb0
#اگر_ختم /* IPTOS_DSCP_VA */
#اگر_غیر_تعریف_شدہ IPTOS_DSCP_EF
# define	IPTOS_DSCP_EF		0xb8
#اگر_ختم /* IPTOS_DSCP_EF */
#اگر_غیر_تعریف_شدہ IPTOS_DSCP_LE
# define	IPTOS_DSCP_LE		0x04
#اگر_ختم /* IPTOS_DSCP_LE */
#اگر_غیر_تعریف_شدہ IPTOS_PREC_CRITIC_ECP
# define IPTOS_PREC_CRITIC_ECP		0xa0
#اگر_ختم
#اگر_غیر_تعریف_شدہ IPTOS_PREC_INTERNETCONTROL
# define IPTOS_PREC_INTERNETCONTROL	0xc0
#اگر_ختم
#اگر_غیر_تعریف_شدہ IPTOS_PREC_NETCONTROL
# define IPTOS_PREC_NETCONTROL		0xe0
#اگر_ختم

#اگر_غیر_تعریف_شدہ PATH_MAX
# ifdef _POSIX_PATH_MAX
# define PATH_MAX _POSIX_PATH_MAX
# endif
#اگر_ختم

#اگر_غیر_تعریف_شدہ MAXPATHLEN
# ifdef PATH_MAX
#  define MAXPATHLEN PATH_MAX
# ورنہ /* PATH_MAX */
#  define MAXPATHLEN 64
# endif /* PATH_MAX */
#اگر_ختم /* MAXPATHLEN */

#اگر_غیر_تعریف_شدہ HOST_NAME_MAX
# include "netdb.h" /* for MAXHOSTNAMELEN */
# اگر defined(_POSIX_HOST_NAME_MAX)
#  define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# elif defined(MAXHOSTNAMELEN)
#  define HOST_NAME_MAX MAXHOSTNAMELEN
# ورنہ
#  define HOST_NAME_MAX	255
# endif
#اگر_ختم /* HOST_NAME_MAX */

#اگر defined(HAVE_DECL_MAXSYMLINKS) && HAVE_DECL_MAXSYMLINKS == 0
# define MAXSYMLINKS 5
#اگر_ختم

#اگر_غیر_تعریف_شدہ STDIN_FILENO
# define STDIN_FILENO    0
#اگر_ختم
#اگر_غیر_تعریف_شدہ STDOUT_FILENO
# define STDOUT_FILENO   1
#اگر_ختم
#اگر_غیر_تعریف_شدہ STDERR_FILENO
# define STDERR_FILENO   2
#اگر_ختم

#اگر_غیر_تعریف_شدہ NGROUPS_MAX	/* Disable groupaccess if NGROUP_MAX is not set */
#اگر_تعریف_شدہ NGROUPS
#تعریف_کرو NGROUPS_MAX NGROUPS
#ورنہ
#تعریف_کرو NGROUPS_MAX 0
#اگر_ختم
#اگر_ختم

#اگر defined(HAVE_DECL_O_NONBLOCK) && HAVE_DECL_O_NONBLOCK == 0
# define O_NONBLOCK      00004	/* Non Blocking Open */
#اگر_ختم

#اگر_غیر_تعریف_شدہ S_IFSOCK
# define S_IFSOCK 0
#اگر_ختم /* S_IFSOCK */

#اگر_غیر_تعریف_شدہ S_ISDIR
# define S_ISDIR(منوال)	(((منوال) & (_S_IFMT)) == (_S_IFDIR))
#اگر_ختم /* S_ISDIR */

#اگر_غیر_تعریف_شدہ S_ISREG
# define S_ISREG(منوال)	(((منوال) & (_S_IFMT)) == (_S_IFREG))
#اگر_ختم /* S_ISREG */

#اگر_غیر_تعریف_شدہ S_ISLNK
# define S_ISLNK(منوال)	(((منوال) & S_IFMT) == S_IFLNK)
#اگر_ختم /* S_ISLNK */

#اگر_غیر_تعریف_شدہ S_IXUSR
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
#اگر_ختم /* S_IXUSR */

#اگر !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
#تعریف_کرو MAP_ANON MAP_ANONYMOUS
#اگر_ختم

#اگر_غیر_تعریف_شدہ MAP_FAILED
# define MAP_FAILED ((خالی *)-1)
#اگر_ختم

/*
SCO Open Server 3 has INADDR_LOOPBACK defined in rpc/rpc.h but
including rpc/rpc.h breaks Solaris 6
*/
#اگر_غیر_تعریف_شدہ INADDR_LOOPBACK
#تعریف_کرو INADDR_LOOPBACK ((u_long)0x7f000001)
#اگر_ختم

/* Types */

/* If sys/types.h does not supply intXX_t, supply them ourselves */
/* (or die trying) */

#اگر_غیر_تعریف_شدہ HAVE_U_INT
قسمتعریف غیرعلامتی مختصر u_short;
قسمتعریف غیرعلامتی صحیح u_int;
قسمتعریف غیرعلامتی طویل u_long;
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_INTXX_T
قسمتعریف علامتی حرف int8_t;
# اگر (SIZEOF_SHORT_INT == 2)
قسمتعریف مختصر صحیح int16_t;
# ورنہ
#   error "16 bit int type not found."
# endif
# اگر (SIZEOF_INT == 4)
قسمتعریف صحیح int32_t;
# ورنہ
#   error "32 bit int type not found."
# endif
#اگر_ختم

/* If sys/types.h does not supply u_intXX_t, supply them ourselves */
#اگر_غیر_تعریف_شدہ HAVE_U_INTXX_T
# ifdef HAVE_UINTXX_T
قسمتعریف uint8_t u_int8_t;
قسمتعریف uint16_t u_int16_t;
قسمتعریف uint32_t u_int32_t;
# define HAVE_U_INTXX_T 1
# ورنہ
قسمتعریف غیرعلامتی حرف u_int8_t;
#  اگر (SIZEOF_SHORT_INT == 2)
قسمتعریف غیرعلامتی مختصر صحیح u_int16_t;
#  ورنہ
#    error "16 bit int type not found."
#  endif
#  اگر (SIZEOF_INT == 4)
قسمتعریف غیرعلامتی صحیح u_int32_t;
#  ورنہ
#    error "32 bit int type not found."
#  endif
# endif
#تعریف_کرو __BIT_TYPES_DEFINED__
#اگر_ختم

#اگر !defined(LLONG_MIN) && defined(LONG_LONG_MIN)
#تعریف_کرو LLONG_MIN LONG_LONG_MIN
#اگر_ختم
#اگر !defined(LLONG_MAX) && defined(LONG_LONG_MAX)
#تعریف_کرو LLONG_MAX LONG_LONG_MAX
#اگر_ختم

#اگر_غیر_تعریف_شدہ UINT32_MAX
# اگر defined(HAVE_DECL_UINT32_MAX) && (HAVE_DECL_UINT32_MAX == 0)
#  اگر (SIZEOF_INT == 4)
#    define UINT32_MAX	UINT_MAX
#  endif
# endif
#اگر_ختم

/* 64-bit types */
#اگر_غیر_تعریف_شدہ HAVE_INT64_T
# اگر (SIZEOF_LONG_INT == 8)
قسمتعریف طویل صحیح int64_t;
# ورنہ
#  اگر (SIZEOF_LONG_LONG_INT == 8)
قسمتعریف طویل طویل صحیح int64_t;
#  endif
# endif
#اگر_ختم
#اگر_غیر_تعریف_شدہ HAVE_U_INT64_T
# اگر (SIZEOF_LONG_INT == 8)
قسمتعریف غیرعلامتی طویل صحیح u_int64_t;
# ورنہ
#  اگر (SIZEOF_LONG_LONG_INT == 8)
قسمتعریف غیرعلامتی طویل طویل صحیح u_int64_t;
#  endif
# endif
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_UINTXX_T
قسمتعریف u_int8_t uint8_t;
قسمتعریف u_int16_t uint16_t;
قسمتعریف u_int32_t uint32_t;
قسمتعریف u_int64_t uint64_t;
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_INTMAX_T
قسمتعریف طویل طویل intmax_t;
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_UINTMAX_T
قسمتعریف غیرعلامتی طویل طویل uintmax_t;
#اگر_ختم

#اگر SIZEOF_وقت_T == SIZEOF_LONG_LONG_INT
# define SSH_وقت_T_MAX LLONG_MAX
#ورنہ
# define SSH_وقت_T_MAX زیادہ_سے_زیادہ_عدد
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_U_CHAR
قسمتعریف غیرعلامتی حرف u_char;
# define HAVE_U_CHAR
#اگر_ختم /* HAVE_U_CHAR */

#اگر_غیر_تعریف_شدہ ULLONG_MAX
# define ULLONG_MAX ((غیرعلامتی طویل طویل)-1)
#اگر_ختم

#اگر_غیر_تعریف_شدہ سائز_T_MAX
#تعریف_کرو سائز_T_MAX ULONG_MAX
#اگر_ختم /* SIZE_T_MAX */

#اگر_غیر_تعریف_شدہ HAVE_سائز_T
قسمتعریف غیرعلامتی صحیح سائز_t;
# define HAVE_سائز_T
# define سائز_T_MAX UINT_MAX
#اگر_ختم /* HAVE_SIZE_T */

#اگر_غیر_تعریف_شدہ SIZE_MAX
#تعریف_کرو SIZE_MAX سائز_T_MAX
#اگر_ختم

#اگر_غیر_تعریف_شدہ INT32_MAX
# اگر (SIZEOF_INT == 4)
#  define INT32_MAX زیادہ_سے_زیادہ_عدد
# elif (SIZEOF_LONG == 4)
#  define INT32_MAX LONG_MAX
# ورنہ
#  error "need INT32_MAX"
# endif
#اگر_ختم

#اگر_غیر_تعریف_شدہ INT64_MAX
# اگر (SIZEOF_INT == 8)
#  define INT64_MAX زیادہ_سے_زیادہ_عدد
# elif (SIZEOF_LONG == 8)
#  define INT64_MAX LONG_MAX
# elif (SIZEOF_LONG_LONG_INT == 8)
#  define INT64_MAX LLONG_MAX
# ورنہ
#  error "need INT64_MAX"
# endif
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_SSIZE_T
قسمتعریف صحیح ssize_t;
#تعریف_کرو SSIZE_MAX زیادہ_سے_زیادہ_عدد
# define HAVE_SSIZE_T
#اگر_ختم /* HAVE_SSIZE_T */

#اگر_غیر_تعریف_شدہ HAVE_CLOCK_T
قسمتعریف طویل clock_t;
# define HAVE_CLOCK_T
#اگر_ختم /* HAVE_CLOCK_T */

#اگر_غیر_تعریف_شدہ HAVE_SA_FAMILY_T
قسمتعریف صحیح sa_family_t;
# define HAVE_SA_FAMILY_T
#اگر_ختم /* HAVE_SA_FAMILY_T */

#اگر_غیر_تعریف_شدہ HAVE_PID_T
قسمتعریف صحیح pid_t;
# define HAVE_PID_T
#اگر_ختم /* HAVE_PID_T */

#اگر_غیر_تعریف_شدہ HAVE_SIG_ATOMIC_T
قسمتعریف صحیح sig_atomic_t;
# define HAVE_SIG_ATOMIC_T
#اگر_ختم /* HAVE_SIG_ATOMIC_T */

#اگر_غیر_تعریف_شدہ HAVE_منوال_T
قسمتعریف صحیح منوال_t;
# define HAVE_منوال_T
#اگر_ختم /* HAVE_MODE_T */

#اگر !defined(HAVE_SS_FAMILY_اندر_SS) && defined(HAVE_SS_FAMILY_اندر_SS_2)
# define ss_family __ss_family
#اگر_ختم /* !defined(HAVE_SS_FAMILY_IN_SS) && defined(HAVE_SA_FAMILY_IN_SS) */

#اگر_غیر_تعریف_شدہ HAVE_SYS_UN_H
ساخت	sockaddr_un {
	مختصر	sun_family;		/* AF_UNIX */
	حرف	sun_راستہ[108];		/* path name (gag) */
};
#اگر_ختم /* HAVE_SYS_UN_H */

#اگر_غیر_تعریف_شدہ HAVE_اندر_ADDR_T
قسمتعریف u_int32_t	in_addr_t;
#اگر_ختم
#اگر_غیر_تعریف_شدہ HAVE_اندر_پورٹ_T
قسمتعریف u_int16_t	in_port_t;
#اگر_ختم

#اگر defined(BROKEN_SYS_TERMIO_H) && !defined(_STRUCT_WINSIZE)
#تعریف_کرو _STRUCT_WINSIZE
ساخت winsize {
      غیرعلامتی مختصر ws_صف;          /* rows, in characters */
      غیرعلامتی مختصر ws_ستون;          /* columns, in character */
      غیرعلامتی مختصر ws_xpixel;       /* horizontal size, pixels */
      غیرعلامتی مختصر ws_ypixel;       /* vertical size, pixels */
};
#اگر_ختم

/* bits needed for select that may not be in the system headers */
#اگر_غیر_تعریف_شدہ HAVE_FD_نقاب
 قسمتعریف غیرعلامتی طویل صحیح	fd_نقاب;
#اگر_ختم

#اگر defined(HAVE_DECL_NFDBITS) && HAVE_DECL_NFDBITS == 0
# define	NFDBITS (8 * حجم(غیرعلامتی طویل))
#اگر_ختم

#اگر defined(HAVE_DECL_HOWMANY) && HAVE_DECL_HOWMANY == 0
# define howmany(x,y)	(((x)+((y)-1))/(y))
#اگر_ختم

/* Paths */

#اگر_غیر_تعریف_شدہ _PATH_BSHELL
# define _PATH_BSHELL "/bin/sh"
#اگر_ختم

#اگر_تعریف_شدہ USER_راستہ
# ifdef _PATH_STDPATH
#  undef _PATH_STDPATH
# endif
# define _PATH_STDPATH USER_راستہ
#اگر_ختم

#اگر_غیر_تعریف_شدہ _PATH_STDPATH
# define _PATH_STDPATH "/usr/bin:/bin:/usr/sbin:/sbin"
#اگر_ختم

#اگر_غیر_تعریف_شدہ SUPERUSER_راستہ
# define SUPERUSER_راستہ	_PATH_STDPATH
#اگر_ختم

#اگر_غیر_تعریف_شدہ _PATH_DEVNULL
# define _PATH_DEVNULL "/dev/null"
#اگر_ختم

/* user may have set a different path */
#اگر defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY)
# undef _PATH_MAILDIR
#اگر_ختم /* defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY) */

#اگر_تعریف_شدہ MAIL_DIRECTORY
# define _PATH_MAILDIR MAIL_DIRECTORY
#اگر_ختم

#اگر_غیر_تعریف_شدہ _PATH_NOLOGIN
# define _PATH_NOLOGIN "/etc/nologin"
#اگر_ختم

/* Define this to be the path of the xauth program. */
#اگر_تعریف_شدہ XAUTH_راستہ
#تعریف_کرو راستہ_XAUTH XAUTH_راستہ
#اگر_ختم /* XAUTH_PATH */

/* derived from XF4/xc/lib/dps/Xlibnet.h */
#اگر_غیر_تعریف_شدہ X_UNIX_راستہ
#  ifdef __hpux
#    define X_UNIX_راستہ "/var/spool/sockets/X11/%u"
#  ورنہ
#    define X_UNIX_راستہ "/tmp/.X11-unix/X%u"
#  endif
#اگر_ختم /* X_UNIX_PATH */
#تعریف_کرو راستہ_UNIX_X X_UNIX_راستہ

#اگر_غیر_تعریف_شدہ _PATH_TTY
# define _PATH_TTY "/dev/tty"
#اگر_ختم

/* Macros */

#اگر defined(HAVE_LOGIN_GETCAPBOOL) && defined(HAVE_LOGIN_CAP_H)
# define HAVE_LOGIN_CAP
#اگر_ختم

#اگر_غیر_تعریف_شدہ MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
# define MIN(a,b) (((a)<(b))?(a):(b))
#اگر_ختم

#اگر_غیر_تعریف_شدہ roundup
# define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#اگر_ختم

#اگر_غیر_تعریف_شدہ timersub
#تعریف_کرو timersub(a, b, نتیجہ)					\
   کرو {								\
      (نتیجہ)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
      (نتیجہ)->tv_usec = (a)->tv_usec - (b)->tv_usec;		\
      اگر ((نتیجہ)->tv_usec < 0) {				\
	 --(نتیجہ)->tv_sec;					\
	 (نتیجہ)->tv_usec += 1000000;				\
      }								\
   } جب (0)
#اگر_ختم

#اگر_غیر_تعریف_شدہ timespeccmp
#تعریف_کرو	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#اگر_ختم

#اگر_غیر_تعریف_شدہ TIMEVAL_مقصد_TIMESPEC
#تعریف_کرو	TIMEVAL_مقصد_TIMESPEC(tv, ts) {					\
	(ts)->tv_sec = (tv)->tv_sec;					\
	(ts)->tv_nsec = (tv)->tv_usec * 1000;				\
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ TIMESPEC_مقصد_TIMEVAL
#تعریف_کرو	TIMESPEC_مقصد_TIMEVAL(tv, ts) {					\
	(tv)->tv_sec = (ts)->tv_sec;					\
	(tv)->tv_usec = (ts)->tv_nsec / 1000;				\
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ timespeccmp
#تعریف_کرو timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#اگر_ختم

/* Operations on timespecs. */
#اگر_غیر_تعریف_شدہ timespecclear
#تعریف_کرو	timespecclear(tsp)		(tsp)->tv_sec = (tsp)->tv_nsec = 0
#اگر_ختم
#اگر_غیر_تعریف_شدہ timespeccmp
#تعریف_کرو	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#اگر_ختم
#اگر_غیر_تعریف_شدہ timespecadd
#تعریف_کرو	timespecadd(tsp, usp, vsp)					\
	کرو {								\
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;	\
		اگر ((vsp)->tv_nsec >= 1000000000L) {			\
			(vsp)->tv_sec++;				\
			(vsp)->tv_nsec -= 1000000000L;			\
		}							\
	} جب (0)
#اگر_ختم
#اگر_غیر_تعریف_شدہ timespecsub
#تعریف_کرو	timespecsub(tsp, usp, vsp)					\
	کرو {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		اگر ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} جب (0)
#اگر_ختم

#اگر_غیر_تعریف_شدہ __P
# define __P(x) x
#اگر_ختم

#اگر !defined(IN6_IS_ADDR_V4MAPPED)
# define IN6_IS_ADDR_V4MAPPED(a) \
	((((u_int32_t *) (a))[0] == 0) && (((u_int32_t *) (a))[1] == 0) && \
	 (((u_int32_t *) (a))[2] == htonl (0xffff)))
#اگر_ختم /* !defined(IN6_IS_ADDR_V4MAPPED) */

#اگر !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#اگر_ختم /* !defined(__GNUC__) || (__GNUC__ < 2) */

#اگر !defined(HAVE_ATTRIBUTE__SENTINEL__) && !defined(__sentinel__)
# define __sentinel__
#اگر_ختم

#اگر !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__bounded__)
# define __bounded__(x, y, z)
#اگر_ختم

#اگر !defined(HAVE_ATTRIBUTE__NONNULL__) && !defined(__nonnull__)
# define __nonnull__(x)
#اگر_ختم

#اگر !defined(HAVE_ATTRIBUTE__NONSTRING__) && !defined(__nonstring__)
# define __nonstring__
#اگر_ختم

#اگر_غیر_تعریف_شدہ OSSH_ALIGNBYTES
#تعریف_کرو OSSH_ALIGNBYTES	(حجم(صحیح) - 1)
#اگر_ختم
#اگر_غیر_تعریف_شدہ __CMSG_ALIGN
#تعریف_کرو	__CMSG_ALIGN(p) (((u_int)(p) + OSSH_ALIGNBYTES) &~ OSSH_ALIGNBYTES)
#اگر_ختم

/* Length of the contents of a control message of length len */
#اگر_غیر_تعریف_شدہ CMSG_LEN
#تعریف_کرو	CMSG_LEN(len)	(__CMSG_ALIGN(حجم(ساخت cmsghdr)) + (len))
#اگر_ختم

/* Length of the space taken up by a padded control message of length len */
#اگر_غیر_تعریف_شدہ CMSG_SPACE
#تعریف_کرو	CMSG_SPACE(len)	(__CMSG_ALIGN(حجم(ساخت cmsghdr)) + __CMSG_ALIGN(len))
#اگر_ختم

/* given pointer to struct cmsghdr, return pointer to data */
#اگر_غیر_تعریف_شدہ CMSG_DATA
#تعریف_کرو CMSG_DATA(cmsg) ((u_char *)(cmsg) + __CMSG_ALIGN(حجم(ساخت cmsghdr)))
#اگر_ختم /* CMSG_DATA */

/*
 * RFC 2292 requires to check msg_controllen, in case that the kernel returns
 * an empty list for some reasons.
 */
#اگر_غیر_تعریف_شدہ CMSG_FIRSTHDR
#تعریف_کرو CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= حجم(ساخت cmsghdr) ? \
	 (ساخت cmsghdr *)(mhdr)->msg_control : \
	 (ساخت cmsghdr *)تہی)
#اگر_ختم /* CMSG_FIRSTHDR */

#اگر defined(HAVE_DECL_OFFSETOF) && HAVE_DECL_OFFSETOF == 0
# define offsetof(type, member) ((سائز_t) &((type *)0)->member)
#اگر_ختم

/* Set up BSD-style BYTE_ORDER definition if it isn't there already */
/* XXX: doesn't try to cope with strange byte orders (PDP_ENDIAN) */
#اگر_غیر_تعریف_شدہ BYTE_ORDER
# ifndef LITTLE_ENDIAN
#  define LITTLE_ENDIAN  1234
# endif /* LITTLE_ENDIAN */
# ifndef BIG_ENDIAN
#  define BIG_ENDIAN     4321
# endif /* BIG_ENDIAN */
# ifdef الفاظ_BIGENDIAN
#  define BYTE_ORDER BIG_ENDIAN
# ورنہ /* WORDS_BIGENDIAN */
#  define BYTE_ORDER LITTLE_ENDIAN
# endif /* WORDS_BIGENDIAN */
#اگر_ختم /* BYTE_ORDER */

#اگر (defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0) || \
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
#  اگر defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) (openssh_swap32(v))
#  endif
#  اگر defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#   define le64toh(v) (openssh_swap64(v))
#  endif
#  اگر defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) (openssh_swap64(v))
#  endif
#  اگر defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) ((uint32_t)v)
#  endif
# ورنہ
#  اگر defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) ((uint32_t)v)
#  endif
#  اگر defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#    define le64toh(v) ((uint64_t)v)
#  endif
#  اگر defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) ((uint64_t)v)
#  endif
#  اگر defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) (openssh_swap32(v))
#  endif
# endif
#اگر_ختم

/* Function replacement / compatibility hacks */

#اگر !defined(HAVE_GETADDRINFO) && (defined(HAVE_OGETADDRINFO) || defined(HAVE_NGETADDRINFO))
# define HAVE_GETADDRINFO
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_GETOPT_OPTRESET
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
#اگر_ختم

#اگر defined(BROKEN_GETADDRINFO) && defined(HAVE_GETADDRINFO)
# undef HAVE_GETADDRINFO
#اگر_ختم
#اگر defined(BROKEN_GETADDRINFO) && defined(HAVE_FREEADDRINFO)
# undef HAVE_FREEADDRINFO
#اگر_ختم
#اگر defined(BROKEN_GETADDRINFO) && defined(HAVE_GAI_STRERROR)
# undef HAVE_GAI_STRERROR
#اگر_ختم

#اگر defined(HAVE_GETADDRINFO)
# اگر defined(HAVE_DECL_AI_NUMERICSERV) && HAVE_DECL_AI_NUMERICSERV == 0
#   define AI_NUMERICSERV	0
# endif
#اگر_ختم

#اگر defined(BROKEN_UPDWTMPX) && defined(HAVE_UPDWTMPX)
# undef HAVE_UPDWTMPX
#اگر_ختم

#اگر defined(BROKEN_SHADOW_EXPIRE) && defined(HAS_SHADOW_EXPIRE)
# undef HAS_SHADOW_EXPIRE
#اگر_ختم

#اگر defined(HAVE_OPENLOG_R) && defined(SYSLOG_ڈیٹا_INIT) && \
    defined(SYSLOG_R_محفوظ_اندر_SIGHAND)
# define DO_LOG_محفوظ_اندر_SIGHAND
#اگر_ختم

#اگر !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY)
# define memmove(s1, s2, n) bcopy((s2), (s1), (n))
#اگر_ختم /* !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY) */

#اگر_غیر_تعریف_شدہ GETPGRP_VOID
# include <unistd.h>
# define getpgrp() getpgrp(0)
#اگر_ختم

#اگر_تعریف_شدہ USE_BSM_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#اگر_ختم

#اگر_تعریف_شدہ USE_LINUX_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#اگر_ختم

#اگر !defined(HAVE___func__) && defined(HAVE___FUNCTION__)
#  define __func__ __FUNCTION__
#وگرنہ_اگر !defined(HAVE___func__)
#  define __func__ ""
#اگر_ختم

#اگر defined(KRB5) && !defined(HEIMDAL)
#  define krb5_get_err_متن(context,رمز) error_پیغام(رمز)
#اگر_ختم

/* Maximum number of file descriptors available */
#اگر_تعریف_شدہ HAVE_SYSCONF
# define SSH_SYSFDMAX sysconf(_SC_OPEN_MAX)
#ورنہ
# define SSH_SYSFDMAX 10000
#اگر_ختم

#اگر_تعریف_شدہ FSID_HAS_VAL
/* encode f_fsid into a 64 bit value  */
#تعریف_کرو FSID_مقصد_ULONG(f) \
	((((u_int64_t)(f).val[0] & 0xffffffffUL) << 32) | \
	    ((f).val[1] & 0xffffffffUL))
#وگرنہ_اگر defined(FSID_HAS___VAL)
#تعریف_کرو FSID_مقصد_ULONG(f) \
	((((u_int64_t)(f).__val[0] & 0xffffffffUL) << 32) | \
	    ((f).__val[1] & 0xffffffffUL))
#ورنہ
# define FSID_مقصد_ULONG(f) ((f))
#اگر_ختم

#اگر defined(__Lynx__)
 /*
  * LynxOS defines these in param.h which we do not want to include since
  * it will also pull in a bunch of kernel definitions.
  */
# define ALIGNBYTES (حجم(صحیح) - 1)
# define ALIGN(p) (((غیرعلامتی)p + ALIGNBYTES) & ~ALIGNBYTES)
  /* Missing prototypes on LynxOS */
  صحیح snprintf (حرف *, سائز_t, ثابت حرف *, ...);
  صحیح mkstemp (حرف *);
  حرف *crypt (ثابت حرف *, ثابت حرف *);
  صحیح seteuid (uid_t);
  صحیح setegid (gid_t);
  حرف *mkdtemp (حرف *);
  صحیح rresvport_af (صحیح *, sa_family_t);
  صحیح innetgr (ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);
#اگر_ختم

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
#اگر_غیر_تعریف_شدہ UTMP_FILE
#  ifdef _PATH_UTMP
#    define UTMP_FILE _PATH_UTMP
#  ورنہ
#    ifdef CONF_UTMP_FILE
#      define UTMP_FILE CONF_UTMP_FILE
#    endif
#  endif
#اگر_ختم
#اگر_غیر_تعریف_شدہ WTMP_FILE
#  ifdef _PATH_WTMP
#    define WTMP_FILE _PATH_WTMP
#  ورنہ
#    ifdef CONF_WTMP_FILE
#      define WTMP_FILE CONF_WTMP_FILE
#    endif
#  endif
#اگر_ختم
/* pick up the user's location for lastlog if given */
#اگر_غیر_تعریف_شدہ LASTLOG_FILE
#  ifdef _PATH_LASTLOG
#    define LASTLOG_FILE _PATH_LASTLOG
#  ورنہ
#    ifdef CONF_LASTLOG_FILE
#      define LASTLOG_FILE CONF_LASTLOG_FILE
#    endif
#  endif
#اگر_ختم

#اگر defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
# define USE_SHADOW
#اگر_ختم

/* The login() library function in libutil is first choice */
#اگر defined(HAVE_LOGIN) && !defined(DISABLE_LOGIN)
#  define USE_LOGIN

#ورنہ
/* Simply select your favourite login types. */
/* Can't do if-else because some systems use several... <sigh> */
#  اگر !defined(DISABLE_UTMPX)
#    define USE_UTMPX
#  endif
#  اگر defined(UTMP_FILE) && !defined(DISABLE_UTMP)
#    define USE_UTMP
#  endif
#  اگر defined(WTMPX_FILE) && !defined(DISABLE_WTMPX)
#    define USE_WTMPX
#  endif
#  اگر defined(WTMP_FILE) && !defined(DISABLE_WTMP)
#    define USE_WTMP
#  endif

#اگر_ختم

#اگر_غیر_تعریف_شدہ UT_LINESIZE
# define UT_LINESIZE 8
#اگر_ختم

/* I hope that the presence of LASTLOG_FILE is enough to detect this */
#اگر defined(LASTLOG_FILE) && !defined(DISABLE_LASTLOG)
#  define USE_LASTLOG
#اگر_ختم

#اگر_تعریف_شدہ HAVE_OSF_SIA
# ifdef USE_SHADOW
#  undef USE_SHADOW
# endif
# define CUSTOM_SYS_AUTH_PASSWD 1
#اگر_ختم

#اگر defined(HAVE_LIBIAF) && defined(HAVE_سیٹ_ID) && !defined(HAVE_SECUREWARE)
# define CUSTOM_SYS_AUTH_PASSWD 1
#اگر_ختم
#اگر defined(HAVE_LIBIAF) && defined(HAVE_سیٹ_ID) && !defined(BROKEN_LIBIAF)
# define USE_LIBIAF
#اگر_ختم

/* HP-UX 11.11 */
#اگر_تعریف_شدہ BTMP_FILE
# define راستہ_BTMP BTMP_FILE
#اگر_ختم

#اگر defined(USE_BTMP) && defined(راستہ_BTMP)
# define CUSTOM_FAILED_LOGIN
#اگر_ختم

/** end of login recorder definitions */

#اگر_تعریف_شدہ BROKEN_GETGROUPS
# define getgroups(a,b) ((a)==0 && (b)==تہی ? NGROUPS_MAX : getgroups((a),(b)))
#اگر_ختم

#اگر_غیر_تعریف_شدہ IOV_MAX
# اگر defined(_XOPEN_IOV_MAX)
#  define	IOV_MAX		_XOPEN_IOV_MAX
# elif defined(DEF_IOV_MAX)
#  define	IOV_MAX		DEF_IOV_MAX
# ورنہ
#  define	IOV_MAX		16
# endif
#اگر_ختم

#اگر_غیر_تعریف_شدہ EWOULDBLOCK
# define EWOULDBLOCK EAGAIN
#اگر_ختم

#اگر_غیر_تعریف_شدہ INET6_ADDRSTRLEN	/* for non IPv6 machines */
#تعریف_کرو INET6_ADDRSTRLEN 46
#اگر_ختم

#اگر_غیر_تعریف_شدہ SSH_IOBUFSZ
# define SSH_IOBUFSZ 8192
#اگر_ختم

/*
 * We want functions in openbsd-compat, if enabled, to override system ones.
 * We no-op out the weak symbol definition rather than remove it to reduce
 * future sync problems.  Some compilers (eg Unixware) do not allow an
 * empty statement, so we use a bogus function declaration.
 */
#تعریف_کرو DEF_WEAK(x)	خالی __ssh_compat_weak_##x(خالی)

/*
 * Platforms that have arc4random_uniform() and not arc4random_stir()
 * shouldn't need the latter.
 */
#اگر defined(HAVE_ARC4RANDOM) && defined(HAVE_ARC4_RANDOM_یکساں) && \
    !defined(HAVE_ARC4RANDOM_STIR)
# define arc4random_stir()
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_VA_COPY
# ifdef HAVE___VA_COPY
#  define va_copy(dest, src) __va_copy(dest, src)
# ورنہ
#  define va_copy(dest, src) (dest) = (src)
# endif
#اگر_ختم

#اگر_غیر_تعریف_شدہ __predict_true
# اگر defined(__GNUC__) && \
     ((__GNUC__ > (2)) || (__GNUC__ == (2) && __GNUC_MINOR__ >= (96)))
#  define __predict_true(قوت_نما)     __builtin_expect(((قوت_نما) != 0), 1)
#  define __predict_false(قوت_نما)    __builtin_expect(((قوت_نما) != 0), 0)
# ورنہ
#  define __predict_true(قوت_نما)     ((قوت_نما) != 0)
#  define __predict_false(قوت_نما)    ((قوت_نما) != 0)
# endif /* gcc version */
#اگر_ختم /* __predict_true */

/*
 * sntrup761 uses variable length arrays and c99-style declarations after code,
 * so only enable if the compiler supports them.
 */
#اگر defined(VARIABLE_لمبائی_ARRAYS) && defined(VARIABLE_DECLARATION_AFTER_رمز)
# define USE_SNTRUP761X25519	1
/* The ML-KEM768 and ML-DSA implementations also uses C89 features */
# define USE_MLKEM768X25519	1
# define USE_MLDSA		1
#اگر_ختم

#اگر defined(HAVE_DECL_INFINITY) && HAVE_DECL_INFINITY == 0
# اگر defined(HAVE_DECL___BUILTIN_INFF) && HAVE_DECL___BUILTIN_INFF == 1
#  define INFINITY __builtin_inff()
# endif
#اگر_ختم

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
#اگر defined(DISABLE_FD_PASSING) && !defined(HAVE_CYGWIN)
# define SKIP_PRIVDROP 1
#اگر_ختم

#اگر_ختم /* _DEFINES_H */
