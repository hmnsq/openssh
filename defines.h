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

#నిర్వచితం_కాకపోతే నిర్వచిస్తుంది_H
#నిర్వచించు నిర్వచిస్తుంది_H

/* Constants */

#ఒకవేళ defined(HAVE_DECL_SHUT_RD) && HAVE_DECL_SHUT_RD == 0
గణన
{
  SHUT_RD = 0,		/* No more receptions.  */
  SHUT_WR,			/* No more transmissions.  */
  SHUT_RDWR			/* No more receptions or transmissions.  */
};
# define SHUT_RD   SHUT_RD
# define SHUT_WR   SHUT_WR
# define SHUT_RDWR SHUT_RDWR
#అయితే_ముగింపు

/*
 * Cygwin doesn't really have a notion of reserved ports.  It is still
 * is useful on the client side so for compatibility it defines as 1024 via
 * netinet/in.h inside an enum.  We * don't actually want that restriction
 * so we want to set that to zero, but we can't do it direct in config.h
 * because it'll cause a conflicting definition the first time we include
 * netinet/in.h.
 */

#నిర్వచితమైతే HAVE_CYGWIN
#నిర్వచించు IPPORT_RESERVED 0
#అయితే_ముగింపు

/*
 * Definitions for IP type of service (ip_tos)
 */
#అన్తర్భావ <netinet/ip.h>
#నిర్వచితం_కాకపోతే IPTOS_LOWDELAY
# define IPTOS_LOWDELAY          0x10
# define IPTOS_THROUGHPUT        0x08
# define IPTOS_RELIABILITY       0x04
# define IPTOS_LOWCOST           0x02
# define IPTOS_MINCOST           IPTOS_LOWCOST
#అయితే_ముగింపు /* IPTOS_LOWDELAY */

/*
 * Definitions for DiffServ Codepoints as per RFCs 2474, 3246, 4594 & 8622.
 * These are the 6 most significant bits as they appear on the wire, so the
 * two least significant bits must be zero.
 */
#నిర్వచితం_కాకపోతే IPTOS_DSCP_AF11
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
#అయితే_ముగింపు /* IPTOS_DSCP_AF11 */
#నిర్వచితం_కాకపోతే IPTOS_DSCP_CS0
# define	IPTOS_DSCP_CS0		0x00
# define	IPTOS_DSCP_CS1		0x20
# define	IPTOS_DSCP_CS2		0x40
# define	IPTOS_DSCP_CS3		0x60
# define	IPTOS_DSCP_CS4		0x80
# define	IPTOS_DSCP_CS5		0xa0
# define	IPTOS_DSCP_CS6		0xc0
# define	IPTOS_DSCP_CS7		0xe0
#అయితే_ముగింపు /* IPTOS_DSCP_CS0 */
#నిర్వచితం_కాకపోతే IPTOS_DSCP_VA
# define	IPTOS_DSCP_VA		0xb0
#అయితే_ముగింపు /* IPTOS_DSCP_VA */
#నిర్వచితం_కాకపోతే IPTOS_DSCP_EF
# define	IPTOS_DSCP_EF		0xb8
#అయితే_ముగింపు /* IPTOS_DSCP_EF */
#నిర్వచితం_కాకపోతే IPTOS_DSCP_LE
# define	IPTOS_DSCP_LE		0x04
#అయితే_ముగింపు /* IPTOS_DSCP_LE */
#నిర్వచితం_కాకపోతే IPTOS_PREC_CRITIC_ECP
# define IPTOS_PREC_CRITIC_ECP		0xa0
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే IPTOS_PREC_INTERNETCONTROL
# define IPTOS_PREC_INTERNETCONTROL	0xc0
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే IPTOS_PREC_NETCONTROL
# define IPTOS_PREC_NETCONTROL		0xe0
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే PATH_MAX
# ifdef _POSIX_PATH_MAX
# define PATH_MAX _POSIX_PATH_MAX
# endif
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే MAXPATHLEN
# ifdef PATH_MAX
#  define MAXPATHLEN PATH_MAX
# లేకపోతే /* PATH_MAX */
#  define MAXPATHLEN 64
# endif /* PATH_MAX */
#అయితే_ముగింపు /* MAXPATHLEN */

#నిర్వచితం_కాకపోతే HOST_NAME_MAX
# include "netdb.h" /* for MAXHOSTNAMELEN */
# ఒకవేళ defined(_POSIX_HOST_NAME_MAX)
#  define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# elif defined(MAXHOSTNAMELEN)
#  define HOST_NAME_MAX MAXHOSTNAMELEN
# లేకపోతే
#  define HOST_NAME_MAX	255
# endif
#అయితే_ముగింపు /* HOST_NAME_MAX */

#ఒకవేళ defined(HAVE_DECL_MAXSYMLINKS) && HAVE_DECL_MAXSYMLINKS == 0
# define MAXSYMLINKS 5
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే STDIN_FILENO
# define STDIN_FILENO    0
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే STDOUT_FILENO
# define STDOUT_FILENO   1
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే STDERR_FILENO
# define STDERR_FILENO   2
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే NGROUPS_MAX	/* Disable groupaccess if NGROUP_MAX is not set */
#నిర్వచితమైతే NGROUPS
#నిర్వచించు NGROUPS_MAX NGROUPS
#లేకపోతే
#నిర్వచించు NGROUPS_MAX 0
#అయితే_ముగింపు
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_DECL_O_NONBLOCK) && HAVE_DECL_O_NONBLOCK == 0
# define O_NONBLOCK      00004	/* Non Blocking Open */
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే S_IFSOCK
# define S_IFSOCK 0
#అయితే_ముగింపు /* S_IFSOCK */

#నిర్వచితం_కాకపోతే S_ISDIR
# define S_ISDIR(బహుళకం)	(((బహుళకం) & (_S_IFMT)) == (_S_IFDIR))
#అయితే_ముగింపు /* S_ISDIR */

#నిర్వచితం_కాకపోతే S_ISREG
# define S_ISREG(బహుళకం)	(((బహుళకం) & (_S_IFMT)) == (_S_IFREG))
#అయితే_ముగింపు /* S_ISREG */

#నిర్వచితం_కాకపోతే S_ISLNK
# define S_ISLNK(బహుళకం)	(((బహుళకం) & S_IFMT) == S_IFLNK)
#అయితే_ముగింపు /* S_ISLNK */

#నిర్వచితం_కాకపోతే S_IXUSR
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
#అయితే_ముగింపు /* S_IXUSR */

#ఒకవేళ !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
#నిర్వచించు MAP_ANON MAP_ANONYMOUS
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే MAP_FAILED
# define MAP_FAILED ((శూన్య *)-1)
#అయితే_ముగింపు

/*
SCO Open Server 3 has INADDR_LOOPBACK defined in rpc/rpc.h but
including rpc/rpc.h breaks Solaris 6
*/
#నిర్వచితం_కాకపోతే INADDR_LOOPBACK
#నిర్వచించు INADDR_LOOPBACK ((u_long)0x7f000001)
#అయితే_ముగింపు

/* Types */

/* If sys/types.h does not supply intXX_t, supply them ourselves */
/* (or die trying) */

#నిర్వచితం_కాకపోతే HAVE_U_INT
రకనిర్వచనం గుర్తులేని పొట్టి u_short;
రకనిర్వచనం గుర్తులేని పూర్ణాంకం u_int;
రకనిర్వచనం గుర్తులేని దీర్ఘ u_long;
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_INTXX_T
రకనిర్వచనం గుర్తుగల అక్షరం int8_t;
# ఒకవేళ (SIZEOF_SHORT_INT == 2)
రకనిర్వచనం పొట్టి పూర్ణాంకం int16_t;
# లేకపోతే
#   error "16 bit int type not found."
# endif
# ఒకవేళ (SIZEOF_INT == 4)
రకనిర్వచనం పూర్ణాంకం int32_t;
# లేకపోతే
#   error "32 bit int type not found."
# endif
#అయితే_ముగింపు

/* If sys/types.h does not supply u_intXX_t, supply them ourselves */
#నిర్వచితం_కాకపోతే HAVE_U_INTXX_T
# ifdef HAVE_UINTXX_T
రకనిర్వచనం uint8_t u_int8_t;
రకనిర్వచనం uint16_t u_int16_t;
రకనిర్వచనం uint32_t u_int32_t;
# define HAVE_U_INTXX_T 1
# లేకపోతే
రకనిర్వచనం గుర్తులేని అక్షరం u_int8_t;
#  ఒకవేళ (SIZEOF_SHORT_INT == 2)
రకనిర్వచనం గుర్తులేని పొట్టి పూర్ణాంకం u_int16_t;
#  లేకపోతే
#    error "16 bit int type not found."
#  endif
#  ఒకవేళ (SIZEOF_INT == 4)
రకనిర్వచనం గుర్తులేని పూర్ణాంకం u_int32_t;
#  లేకపోతే
#    error "32 bit int type not found."
#  endif
# endif
#నిర్వచించు __BIT_TYPES_DEFINED__
#అయితే_ముగింపు

#ఒకవేళ !defined(LLONG_MIN) && defined(LONG_LONG_MIN)
#నిర్వచించు LLONG_MIN LONG_LONG_MIN
#అయితే_ముగింపు
#ఒకవేళ !defined(LLONG_MAX) && defined(LONG_LONG_MAX)
#నిర్వచించు LLONG_MAX LONG_LONG_MAX
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే UINT32_MAX
# ఒకవేళ defined(HAVE_DECL_UINT32_MAX) && (HAVE_DECL_UINT32_MAX == 0)
#  ఒకవేళ (SIZEOF_INT == 4)
#    define UINT32_MAX	UINT_MAX
#  endif
# endif
#అయితే_ముగింపు

/* 64-bit types */
#నిర్వచితం_కాకపోతే HAVE_INT64_T
# ఒకవేళ (SIZEOF_LONG_INT == 8)
రకనిర్వచనం దీర్ఘ పూర్ణాంకం int64_t;
# లేకపోతే
#  ఒకవేళ (SIZEOF_LONG_LONG_INT == 8)
రకనిర్వచనం దీర్ఘ దీర్ఘ పూర్ణాంకం int64_t;
#  endif
# endif
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే HAVE_U_INT64_T
# ఒకవేళ (SIZEOF_LONG_INT == 8)
రకనిర్వచనం గుర్తులేని దీర్ఘ పూర్ణాంకం u_int64_t;
# లేకపోతే
#  ఒకవేళ (SIZEOF_LONG_LONG_INT == 8)
రకనిర్వచనం గుర్తులేని దీర్ఘ దీర్ఘ పూర్ణాంకం u_int64_t;
#  endif
# endif
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_UINTXX_T
రకనిర్వచనం u_int8_t uint8_t;
రకనిర్వచనం u_int16_t uint16_t;
రకనిర్వచనం u_int32_t uint32_t;
రకనిర్వచనం u_int64_t uint64_t;
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_INTMAX_T
రకనిర్వచనం దీర్ఘ దీర్ఘ intmax_t;
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_UINTMAX_T
రకనిర్వచనం గుర్తులేని దీర్ఘ దీర్ఘ uintmax_t;
#అయితే_ముగింపు

#ఒకవేళ SIZEOF_సమయం_T == SIZEOF_LONG_LONG_INT
# define SSH_సమయం_T_MAX LLONG_MAX
#లేకపోతే
# define SSH_సమయం_T_MAX గరిష్ఠ_పూర్ణాంకం
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_U_CHAR
రకనిర్వచనం గుర్తులేని అక్షరం u_char;
# define HAVE_U_CHAR
#అయితే_ముగింపు /* HAVE_U_CHAR */

#నిర్వచితం_కాకపోతే ULLONG_MAX
# define ULLONG_MAX ((గుర్తులేని దీర్ఘ దీర్ఘ)-1)
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే కొలత_T_MAX
#నిర్వచించు కొలత_T_MAX ULONG_MAX
#అయితే_ముగింపు /* SIZE_T_MAX */

#నిర్వచితం_కాకపోతే HAVE_కొలత_T
రకనిర్వచనం గుర్తులేని పూర్ణాంకం కొలత_t;
# define HAVE_కొలత_T
# define కొలత_T_MAX UINT_MAX
#అయితే_ముగింపు /* HAVE_SIZE_T */

#నిర్వచితం_కాకపోతే SIZE_MAX
#నిర్వచించు SIZE_MAX కొలత_T_MAX
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే INT32_MAX
# ఒకవేళ (SIZEOF_INT == 4)
#  define INT32_MAX గరిష్ఠ_పూర్ణాంకం
# elif (SIZEOF_LONG == 4)
#  define INT32_MAX LONG_MAX
# లేకపోతే
#  error "need INT32_MAX"
# endif
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే INT64_MAX
# ఒకవేళ (SIZEOF_INT == 8)
#  define INT64_MAX గరిష్ఠ_పూర్ణాంకం
# elif (SIZEOF_LONG == 8)
#  define INT64_MAX LONG_MAX
# elif (SIZEOF_LONG_LONG_INT == 8)
#  define INT64_MAX LLONG_MAX
# లేకపోతే
#  error "need INT64_MAX"
# endif
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_SSIZE_T
రకనిర్వచనం పూర్ణాంకం ssize_t;
#నిర్వచించు SSIZE_MAX గరిష్ఠ_పూర్ణాంకం
# define HAVE_SSIZE_T
#అయితే_ముగింపు /* HAVE_SSIZE_T */

#నిర్వచితం_కాకపోతే HAVE_CLOCK_T
రకనిర్వచనం దీర్ఘ clock_t;
# define HAVE_CLOCK_T
#అయితే_ముగింపు /* HAVE_CLOCK_T */

#నిర్వచితం_కాకపోతే HAVE_SA_FAMILY_T
రకనిర్వచనం పూర్ణాంకం sa_family_t;
# define HAVE_SA_FAMILY_T
#అయితే_ముగింపు /* HAVE_SA_FAMILY_T */

#నిర్వచితం_కాకపోతే HAVE_PID_T
రకనిర్వచనం పూర్ణాంకం pid_t;
# define HAVE_PID_T
#అయితే_ముగింపు /* HAVE_PID_T */

#నిర్వచితం_కాకపోతే HAVE_SIG_ATOMIC_T
రకనిర్వచనం పూర్ణాంకం sig_atomic_t;
# define HAVE_SIG_ATOMIC_T
#అయితే_ముగింపు /* HAVE_SIG_ATOMIC_T */

#నిర్వచితం_కాకపోతే HAVE_బహుళకం_T
రకనిర్వచనం పూర్ణాంకం బహుళకం_t;
# define HAVE_బహుళకం_T
#అయితే_ముగింపు /* HAVE_MODE_T */

#ఒకవేళ !defined(HAVE_SS_FAMILY_లోపల_SS) && defined(HAVE_SS_FAMILY_లోపల_SS_2)
# define ss_family __ss_family
#అయితే_ముగింపు /* !defined(HAVE_SS_FAMILY_IN_SS) && defined(HAVE_SA_FAMILY_IN_SS) */

#నిర్వచితం_కాకపోతే HAVE_SYS_UN_H
నిర్మాణం	sockaddr_un {
	పొట్టి	sun_family;		/* AF_UNIX */
	అక్షరం	sun_మార్గం[108];		/* path name (gag) */
};
#అయితే_ముగింపు /* HAVE_SYS_UN_H */

#నిర్వచితం_కాకపోతే HAVE_లోపల_ADDR_T
రకనిర్వచనం u_int32_t	in_addr_t;
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే HAVE_లోపల_పోర్టు_T
రకనిర్వచనం u_int16_t	in_port_t;
#అయితే_ముగింపు

#ఒకవేళ defined(BROKEN_SYS_TERMIO_H) && !defined(_STRUCT_WINSIZE)
#నిర్వచించు _STRUCT_WINSIZE
నిర్మాణం winsize {
      గుర్తులేని పొట్టి ws_అడ్డువరుస;          /* rows, in characters */
      గుర్తులేని పొట్టి ws_నిలువు;          /* columns, in character */
      గుర్తులేని పొట్టి ws_xpixel;       /* horizontal size, pixels */
      గుర్తులేని పొట్టి ws_ypixel;       /* vertical size, pixels */
};
#అయితే_ముగింపు

/* bits needed for select that may not be in the system headers */
#నిర్వచితం_కాకపోతే HAVE_FD_ముసుగు
 రకనిర్వచనం గుర్తులేని దీర్ఘ పూర్ణాంకం	fd_ముసుగు;
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_DECL_NFDBITS) && HAVE_DECL_NFDBITS == 0
# define	NFDBITS (8 * పరిమాణం(గుర్తులేని దీర్ఘ))
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_DECL_HOWMANY) && HAVE_DECL_HOWMANY == 0
# define howmany(x,y)	(((x)+((y)-1))/(y))
#అయితే_ముగింపు

/* Paths */

#నిర్వచితం_కాకపోతే _PATH_BSHELL
# define _PATH_BSHELL "/bin/sh"
#అయితే_ముగింపు

#నిర్వచితమైతే USER_మార్గం
# ifdef _PATH_STDPATH
#  undef _PATH_STDPATH
# endif
# define _PATH_STDPATH USER_మార్గం
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే _PATH_STDPATH
# define _PATH_STDPATH "/usr/bin:/bin:/usr/sbin:/sbin"
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే SUPERUSER_మార్గం
# define SUPERUSER_మార్గం	_PATH_STDPATH
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే _PATH_DEVNULL
# define _PATH_DEVNULL "/dev/null"
#అయితే_ముగింపు

/* user may have set a different path */
#ఒకవేళ defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY)
# undef _PATH_MAILDIR
#అయితే_ముగింపు /* defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY) */

#నిర్వచితమైతే MAIL_DIRECTORY
# define _PATH_MAILDIR MAIL_DIRECTORY
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే _PATH_NOLOGIN
# define _PATH_NOLOGIN "/etc/nologin"
#అయితే_ముగింపు

/* Define this to be the path of the xauth program. */
#నిర్వచితమైతే XAUTH_మార్గం
#నిర్వచించు మార్గం_XAUTH XAUTH_మార్గం
#అయితే_ముగింపు /* XAUTH_PATH */

/* derived from XF4/xc/lib/dps/Xlibnet.h */
#నిర్వచితం_కాకపోతే X_UNIX_మార్గం
#  ifdef __hpux
#    define X_UNIX_మార్గం "/var/spool/sockets/X11/%u"
#  లేకపోతే
#    define X_UNIX_మార్గం "/tmp/.X11-unix/X%u"
#  endif
#అయితే_ముగింపు /* X_UNIX_PATH */
#నిర్వచించు మార్గం_UNIX_X X_UNIX_మార్గం

#నిర్వచితం_కాకపోతే _PATH_TTY
# define _PATH_TTY "/dev/tty"
#అయితే_ముగింపు

/* Macros */

#ఒకవేళ defined(HAVE_LOGIN_GETCAPBOOL) && defined(HAVE_LOGIN_CAP_H)
# define HAVE_LOGIN_CAP
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
# define MIN(a,b) (((a)<(b))?(a):(b))
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే roundup
# define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే timersub
#నిర్వచించు timersub(a, b, ఫలితం)					\
   చేయి {								\
      (ఫలితం)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
      (ఫలితం)->tv_usec = (a)->tv_usec - (b)->tv_usec;		\
      ఒకవేళ ((ఫలితం)->tv_usec < 0) {				\
	 --(ఫలితం)->tv_sec;					\
	 (ఫలితం)->tv_usec += 1000000;				\
      }								\
   } అయితే (0)
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే timespeccmp
#నిర్వచించు	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే TIMEVAL_గమ్యం_TIMESPEC
#నిర్వచించు	TIMEVAL_గమ్యం_TIMESPEC(tv, ts) {					\
	(ts)->tv_sec = (tv)->tv_sec;					\
	(ts)->tv_nsec = (tv)->tv_usec * 1000;				\
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే TIMESPEC_గమ్యం_TIMEVAL
#నిర్వచించు	TIMESPEC_గమ్యం_TIMEVAL(tv, ts) {					\
	(tv)->tv_sec = (ts)->tv_sec;					\
	(tv)->tv_usec = (ts)->tv_nsec / 1000;				\
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే timespeccmp
#నిర్వచించు timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#అయితే_ముగింపు

/* Operations on timespecs. */
#నిర్వచితం_కాకపోతే timespecclear
#నిర్వచించు	timespecclear(tsp)		(tsp)->tv_sec = (tsp)->tv_nsec = 0
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే timespeccmp
#నిర్వచించు	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే timespecadd
#నిర్వచించు	timespecadd(tsp, usp, vsp)					\
	చేయి {								\
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;	\
		ఒకవేళ ((vsp)->tv_nsec >= 1000000000L) {			\
			(vsp)->tv_sec++;				\
			(vsp)->tv_nsec -= 1000000000L;			\
		}							\
	} అయితే (0)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే timespecsub
#నిర్వచించు	timespecsub(tsp, usp, vsp)					\
	చేయి {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		ఒకవేళ ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} అయితే (0)
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే __P
# define __P(x) x
#అయితే_ముగింపు

#ఒకవేళ !defined(IN6_IS_ADDR_V4MAPPED)
# define IN6_IS_ADDR_V4MAPPED(a) \
	((((u_int32_t *) (a))[0] == 0) && (((u_int32_t *) (a))[1] == 0) && \
	 (((u_int32_t *) (a))[2] == htonl (0xffff)))
#అయితే_ముగింపు /* !defined(IN6_IS_ADDR_V4MAPPED) */

#ఒకవేళ !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#అయితే_ముగింపు /* !defined(__GNUC__) || (__GNUC__ < 2) */

#ఒకవేళ !defined(HAVE_ATTRIBUTE__SENTINEL__) && !defined(__sentinel__)
# define __sentinel__
#అయితే_ముగింపు

#ఒకవేళ !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__bounded__)
# define __bounded__(x, y, z)
#అయితే_ముగింపు

#ఒకవేళ !defined(HAVE_ATTRIBUTE__NONNULL__) && !defined(__nonnull__)
# define __nonnull__(x)
#అయితే_ముగింపు

#ఒకవేళ !defined(HAVE_ATTRIBUTE__NONSTRING__) && !defined(__nonstring__)
# define __nonstring__
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే OSSH_ALIGNBYTES
#నిర్వచించు OSSH_ALIGNBYTES	(పరిమాణం(పూర్ణాంకం) - 1)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే __CMSG_ALIGN
#నిర్వచించు	__CMSG_ALIGN(p) (((u_int)(p) + OSSH_ALIGNBYTES) &~ OSSH_ALIGNBYTES)
#అయితే_ముగింపు

/* Length of the contents of a control message of length len */
#నిర్వచితం_కాకపోతే CMSG_LEN
#నిర్వచించు	CMSG_LEN(len)	(__CMSG_ALIGN(పరిమాణం(నిర్మాణం cmsghdr)) + (len))
#అయితే_ముగింపు

/* Length of the space taken up by a padded control message of length len */
#నిర్వచితం_కాకపోతే CMSG_SPACE
#నిర్వచించు	CMSG_SPACE(len)	(__CMSG_ALIGN(పరిమాణం(నిర్మాణం cmsghdr)) + __CMSG_ALIGN(len))
#అయితే_ముగింపు

/* given pointer to struct cmsghdr, return pointer to data */
#నిర్వచితం_కాకపోతే CMSG_DATA
#నిర్వచించు CMSG_DATA(cmsg) ((u_char *)(cmsg) + __CMSG_ALIGN(పరిమాణం(నిర్మాణం cmsghdr)))
#అయితే_ముగింపు /* CMSG_DATA */

/*
 * RFC 2292 requires to check msg_controllen, in case that the kernel returns
 * an empty list for some reasons.
 */
#నిర్వచితం_కాకపోతే CMSG_FIRSTHDR
#నిర్వచించు CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= పరిమాణం(నిర్మాణం cmsghdr) ? \
	 (నిర్మాణం cmsghdr *)(mhdr)->msg_control : \
	 (నిర్మాణం cmsghdr *)ఖాళీ)
#అయితే_ముగింపు /* CMSG_FIRSTHDR */

#ఒకవేళ defined(HAVE_DECL_OFFSETOF) && HAVE_DECL_OFFSETOF == 0
# define offsetof(type, member) ((కొలత_t) &((type *)0)->member)
#అయితే_ముగింపు

/* Set up BSD-style BYTE_ORDER definition if it isn't there already */
/* XXX: doesn't try to cope with strange byte orders (PDP_ENDIAN) */
#నిర్వచితం_కాకపోతే BYTE_ORDER
# ifndef LITTLE_ENDIAN
#  define LITTLE_ENDIAN  1234
# endif /* LITTLE_ENDIAN */
# ifndef BIG_ENDIAN
#  define BIG_ENDIAN     4321
# endif /* BIG_ENDIAN */
# ifdef పదాలు_BIGENDIAN
#  define BYTE_ORDER BIG_ENDIAN
# లేకపోతే /* WORDS_BIGENDIAN */
#  define BYTE_ORDER LITTLE_ENDIAN
# endif /* WORDS_BIGENDIAN */
#అయితే_ముగింపు /* BYTE_ORDER */

#ఒకవేళ (defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0) || \
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
# ifdef పదాలు_BIGENDIAN
#  ఒకవేళ defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) (openssh_swap32(v))
#  endif
#  ఒకవేళ defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#   define le64toh(v) (openssh_swap64(v))
#  endif
#  ఒకవేళ defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) (openssh_swap64(v))
#  endif
#  ఒకవేళ defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) ((uint32_t)v)
#  endif
# లేకపోతే
#  ఒకవేళ defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) ((uint32_t)v)
#  endif
#  ఒకవేళ defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#    define le64toh(v) ((uint64_t)v)
#  endif
#  ఒకవేళ defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) ((uint64_t)v)
#  endif
#  ఒకవేళ defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) (openssh_swap32(v))
#  endif
# endif
#అయితే_ముగింపు

/* Function replacement / compatibility hacks */

#ఒకవేళ !defined(HAVE_GETADDRINFO) && (defined(HAVE_OGETADDRINFO) || defined(HAVE_NGETADDRINFO))
# define HAVE_GETADDRINFO
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_GETOPT_OPTRESET
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
#అయితే_ముగింపు

#ఒకవేళ defined(BROKEN_GETADDRINFO) && defined(HAVE_GETADDRINFO)
# undef HAVE_GETADDRINFO
#అయితే_ముగింపు
#ఒకవేళ defined(BROKEN_GETADDRINFO) && defined(HAVE_FREEADDRINFO)
# undef HAVE_FREEADDRINFO
#అయితే_ముగింపు
#ఒకవేళ defined(BROKEN_GETADDRINFO) && defined(HAVE_GAI_STRERROR)
# undef HAVE_GAI_STRERROR
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_GETADDRINFO)
# ఒకవేళ defined(HAVE_DECL_AI_NUMERICSERV) && HAVE_DECL_AI_NUMERICSERV == 0
#   define AI_NUMERICSERV	0
# endif
#అయితే_ముగింపు

#ఒకవేళ defined(BROKEN_UPDWTMPX) && defined(HAVE_UPDWTMPX)
# undef HAVE_UPDWTMPX
#అయితే_ముగింపు

#ఒకవేళ defined(BROKEN_SHADOW_EXPIRE) && defined(HAS_SHADOW_EXPIRE)
# undef HAS_SHADOW_EXPIRE
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_OPENLOG_R) && defined(SYSLOG_దత్తాంశం_INIT) && \
    defined(SYSLOG_R_సురక్షిత_లోపల_SIGHAND)
# define DO_LOG_సురక్షిత_లోపల_SIGHAND
#అయితే_ముగింపు

#ఒకవేళ !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY)
# define memmove(s1, s2, n) bcopy((s2), (s1), (n))
#అయితే_ముగింపు /* !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY) */

#నిర్వచితం_కాకపోతే GETPGRP_VOID
# include <unistd.h>
# define getpgrp() getpgrp(0)
#అయితే_ముగింపు

#నిర్వచితమైతే USE_BSM_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#అయితే_ముగింపు

#నిర్వచితమైతే USE_LINUX_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#అయితే_ముగింపు

#ఒకవేళ !defined(HAVE___func__) && defined(HAVE___FUNCTION__)
#  define __func__ __FUNCTION__
#లేదావేళ !defined(HAVE___func__)
#  define __func__ ""
#అయితే_ముగింపు

#ఒకవేళ defined(KRB5) && !defined(HEIMDAL)
#  define krb5_get_err_పాఠ్యం(context,సంకేతం_2) error_సందేశం(సంకేతం_2)
#అయితే_ముగింపు

/* Maximum number of file descriptors available */
#నిర్వచితమైతే HAVE_SYSCONF
# define SSH_SYSFDMAX sysconf(_SC_OPEN_MAX)
#లేకపోతే
# define SSH_SYSFDMAX 10000
#అయితే_ముగింపు

#నిర్వచితమైతే FSID_HAS_VAL
/* encode f_fsid into a 64 bit value  */
#నిర్వచించు FSID_గమ్యం_ULONG(f) \
	((((u_int64_t)(f).val[0] & 0xffffffffUL) << 32) | \
	    ((f).val[1] & 0xffffffffUL))
#లేదావేళ defined(FSID_HAS___VAL)
#నిర్వచించు FSID_గమ్యం_ULONG(f) \
	((((u_int64_t)(f).__val[0] & 0xffffffffUL) << 32) | \
	    ((f).__val[1] & 0xffffffffUL))
#లేకపోతే
# define FSID_గమ్యం_ULONG(f) ((f))
#అయితే_ముగింపు

#ఒకవేళ defined(__Lynx__)
 /*
  * LynxOS defines these in param.h which we do not want to include since
  * it will also pull in a bunch of kernel definitions.
  */
# define ALIGNBYTES (పరిమాణం(పూర్ణాంకం) - 1)
# define ALIGN(p) (((గుర్తులేని)p + ALIGNBYTES) & ~ALIGNBYTES)
  /* Missing prototypes on LynxOS */
  పూర్ణాంకం snprintf (అక్షరం *, కొలత_t, స్థిరరాశి అక్షరం *, ...);
  పూర్ణాంకం mkstemp (అక్షరం *);
  అక్షరం *crypt (స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
  పూర్ణాంకం seteuid (uid_t);
  పూర్ణాంకం setegid (gid_t);
  అక్షరం *mkdtemp (అక్షరం *);
  పూర్ణాంకం rresvport_af (పూర్ణాంకం *, sa_family_t);
  పూర్ణాంకం innetgr (స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
#అయితే_ముగింపు

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
#నిర్వచితం_కాకపోతే UTMP_FILE
#  ifdef _PATH_UTMP
#    define UTMP_FILE _PATH_UTMP
#  లేకపోతే
#    ifdef CONF_UTMP_FILE
#      define UTMP_FILE CONF_UTMP_FILE
#    endif
#  endif
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే WTMP_FILE
#  ifdef _PATH_WTMP
#    define WTMP_FILE _PATH_WTMP
#  లేకపోతే
#    ifdef CONF_WTMP_FILE
#      define WTMP_FILE CONF_WTMP_FILE
#    endif
#  endif
#అయితే_ముగింపు
/* pick up the user's location for lastlog if given */
#నిర్వచితం_కాకపోతే LASTLOG_FILE
#  ifdef _PATH_LASTLOG
#    define LASTLOG_FILE _PATH_LASTLOG
#  లేకపోతే
#    ifdef CONF_LASTLOG_FILE
#      define LASTLOG_FILE CONF_LASTLOG_FILE
#    endif
#  endif
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
# define USE_SHADOW
#అయితే_ముగింపు

/* The login() library function in libutil is first choice */
#ఒకవేళ defined(HAVE_LOGIN) && !defined(DISABLE_LOGIN)
#  define USE_LOGIN

#లేకపోతే
/* Simply select your favourite login types. */
/* Can't do if-else because some systems use several... <sigh> */
#  ఒకవేళ !defined(DISABLE_UTMPX)
#    define USE_UTMPX
#  endif
#  ఒకవేళ defined(UTMP_FILE) && !defined(DISABLE_UTMP)
#    define USE_UTMP
#  endif
#  ఒకవేళ defined(WTMPX_FILE) && !defined(DISABLE_WTMPX)
#    define USE_WTMPX
#  endif
#  ఒకవేళ defined(WTMP_FILE) && !defined(DISABLE_WTMP)
#    define USE_WTMP
#  endif

#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే UT_LINESIZE
# define UT_LINESIZE 8
#అయితే_ముగింపు

/* I hope that the presence of LASTLOG_FILE is enough to detect this */
#ఒకవేళ defined(LASTLOG_FILE) && !defined(DISABLE_LASTLOG)
#  define USE_LASTLOG
#అయితే_ముగింపు

#నిర్వచితమైతే HAVE_OSF_SIA
# ifdef USE_SHADOW
#  undef USE_SHADOW
# endif
# define CUSTOM_SYS_AUTH_PASSWD 1
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_LIBIAF) && defined(HAVE_సమితి_ID) && !defined(HAVE_SECUREWARE)
# define CUSTOM_SYS_AUTH_PASSWD 1
#అయితే_ముగింపు
#ఒకవేళ defined(HAVE_LIBIAF) && defined(HAVE_సమితి_ID) && !defined(BROKEN_LIBIAF)
# define USE_LIBIAF
#అయితే_ముగింపు

/* HP-UX 11.11 */
#నిర్వచితమైతే BTMP_FILE
# define మార్గం_BTMP BTMP_FILE
#అయితే_ముగింపు

#ఒకవేళ defined(USE_BTMP) && defined(మార్గం_BTMP)
# define CUSTOM_FAILED_LOGIN
#అయితే_ముగింపు

/** end of login recorder definitions */

#నిర్వచితమైతే BROKEN_GETGROUPS
# define getgroups(a,b) ((a)==0 && (b)==ఖాళీ ? NGROUPS_MAX : getgroups((a),(b)))
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే IOV_MAX
# ఒకవేళ defined(_XOPEN_IOV_MAX)
#  define	IOV_MAX		_XOPEN_IOV_MAX
# elif defined(DEF_IOV_MAX)
#  define	IOV_MAX		DEF_IOV_MAX
# లేకపోతే
#  define	IOV_MAX		16
# endif
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే EWOULDBLOCK
# define EWOULDBLOCK EAGAIN
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే INET6_ADDRSTRLEN	/* for non IPv6 machines */
#నిర్వచించు INET6_ADDRSTRLEN 46
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే SSH_IOBUFSZ
# define SSH_IOBUFSZ 8192
#అయితే_ముగింపు

/*
 * We want functions in openbsd-compat, if enabled, to override system ones.
 * We no-op out the weak symbol definition rather than remove it to reduce
 * future sync problems.  Some compilers (eg Unixware) do not allow an
 * empty statement, so we use a bogus function declaration.
 */
#నిర్వచించు DEF_WEAK(x)	శూన్య __ssh_compat_weak_##x(శూన్య)

/*
 * Platforms that have arc4random_uniform() and not arc4random_stir()
 * shouldn't need the latter.
 */
#ఒకవేళ defined(HAVE_ARC4RANDOM) && defined(HAVE_ARC4_RANDOM_ఏకరీతి) && \
    !defined(HAVE_ARC4RANDOM_STIR)
# define arc4random_stir()
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_VA_COPY
# ifdef HAVE___VA_COPY
#  define va_copy(dest, src) __va_copy(dest, src)
# లేకపోతే
#  define va_copy(dest, src) (dest) = (src)
# endif
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే __predict_true
# ఒకవేళ defined(__GNUC__) && \
     ((__GNUC__ > (2)) || (__GNUC__ == (2) && __GNUC_MINOR__ >= (96)))
#  define __predict_true(ఘాతాంకం)     __builtin_expect(((ఘాతాంకం) != 0), 1)
#  define __predict_false(ఘాతాంకం)    __builtin_expect(((ఘాతాంకం) != 0), 0)
# లేకపోతే
#  define __predict_true(ఘాతాంకం)     ((ఘాతాంకం) != 0)
#  define __predict_false(ఘాతాంకం)    ((ఘాతాంకం) != 0)
# endif /* gcc version */
#అయితే_ముగింపు /* __predict_true */

/*
 * sntrup761 uses variable length arrays and c99-style declarations after code,
 * so only enable if the compiler supports them.
 */
#ఒకవేళ defined(VARIABLE_నిడివి_ARRAYS) && defined(VARIABLE_DECLARATION_AFTER_సంకేతం)
# define USE_SNTRUP761X25519	1
/* The ML-KEM768 and ML-DSA implementations also uses C89 features */
# define USE_MLKEM768X25519	1
# define USE_MLDSA		1
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_DECL_INFINITY) && HAVE_DECL_INFINITY == 0
# ఒకవేళ defined(HAVE_DECL___BUILTIN_INFF) && HAVE_DECL___BUILTIN_INFF == 1
#  define INFINITY __builtin_inff()
# endif
#అయితే_ముగింపు

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
#ఒకవేళ defined(DISABLE_FD_PASSING) && !defined(HAVE_CYGWIN)
# define SKIP_PRIVDROP 1
#అయితే_ముగింపు

#అయితే_ముగింపు /* _DEFINES_H */
