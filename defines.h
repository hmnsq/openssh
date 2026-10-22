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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ನಿರೂಪಿಸುತ್ತದೆ_H
#ವ್ಯಾಖ್ಯಾನಿಸು ನಿರೂಪಿಸುತ್ತದೆ_H

/* Constants */

#ಆದರೆ defined(HAVE_DECL_SHUT_RD) && HAVE_DECL_SHUT_RD == 0
ಎಣಿಕೆ
{
  SHUT_RD = 0,		/* No more receptions.  */
  SHUT_WR,			/* No more transmissions.  */
  SHUT_RDWR			/* No more receptions or transmissions.  */
};
# define SHUT_RD   SHUT_RD
# define SHUT_WR   SHUT_WR
# define SHUT_RDWR SHUT_RDWR
#ಆದರೆ_ಅಂತ್ಯ

/*
 * Cygwin doesn't really have a notion of reserved ports.  It is still
 * is useful on the client side so for compatibility it defines as 1024 via
 * netinet/in.h inside an enum.  We * don't actually want that restriction
 * so we want to set that to zero, but we can't do it direct in config.h
 * because it'll cause a conflicting definition the first time we include
 * netinet/in.h.
 */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN
#ವ್ಯಾಖ್ಯಾನಿಸು IPPORT_RESERVED 0
#ಆದರೆ_ಅಂತ್ಯ

/*
 * Definitions for IP type of service (ip_tos)
 */
#ಅನ್ತರ್ಭಾವ <netinet/ip.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ IPTOS_LOWDELAY
# define IPTOS_LOWDELAY          0x10
# define IPTOS_THROUGHPUT        0x08
# define IPTOS_RELIABILITY       0x04
# define IPTOS_LOWCOST           0x02
# define IPTOS_MINCOST           IPTOS_LOWCOST
#ಆದರೆ_ಅಂತ್ಯ /* IPTOS_LOWDELAY */

/*
 * Definitions for DiffServ Codepoints as per RFCs 2474, 3246, 4594 & 8622.
 * These are the 6 most significant bits as they appear on the wire, so the
 * two least significant bits must be zero.
 */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ IPTOS_DSCP_AF11
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
#ಆದರೆ_ಅಂತ್ಯ /* IPTOS_DSCP_AF11 */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ IPTOS_DSCP_CS0
# define	IPTOS_DSCP_CS0		0x00
# define	IPTOS_DSCP_CS1		0x20
# define	IPTOS_DSCP_CS2		0x40
# define	IPTOS_DSCP_CS3		0x60
# define	IPTOS_DSCP_CS4		0x80
# define	IPTOS_DSCP_CS5		0xa0
# define	IPTOS_DSCP_CS6		0xc0
# define	IPTOS_DSCP_CS7		0xe0
#ಆದರೆ_ಅಂತ್ಯ /* IPTOS_DSCP_CS0 */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ IPTOS_DSCP_VA
# define	IPTOS_DSCP_VA		0xb0
#ಆದರೆ_ಅಂತ್ಯ /* IPTOS_DSCP_VA */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ IPTOS_DSCP_EF
# define	IPTOS_DSCP_EF		0xb8
#ಆದರೆ_ಅಂತ್ಯ /* IPTOS_DSCP_EF */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ IPTOS_DSCP_LE
# define	IPTOS_DSCP_LE		0x04
#ಆದರೆ_ಅಂತ್ಯ /* IPTOS_DSCP_LE */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ IPTOS_PREC_CRITIC_ECP
# define IPTOS_PREC_CRITIC_ECP		0xa0
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ IPTOS_PREC_INTERNETCONTROL
# define IPTOS_PREC_INTERNETCONTROL	0xc0
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ IPTOS_PREC_NETCONTROL
# define IPTOS_PREC_NETCONTROL		0xe0
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ PATH_MAX
# ifdef _POSIX_PATH_MAX
# define PATH_MAX _POSIX_PATH_MAX
# endif
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ MAXPATHLEN
# ifdef PATH_MAX
#  define MAXPATHLEN PATH_MAX
# ಇಲ್ಲದಿದ್ದರೆ /* PATH_MAX */
#  define MAXPATHLEN 64
# endif /* PATH_MAX */
#ಆದರೆ_ಅಂತ್ಯ /* MAXPATHLEN */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HOST_NAME_MAX
# include "netdb.h" /* for MAXHOSTNAMELEN */
# ಆದರೆ defined(_POSIX_HOST_NAME_MAX)
#  define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# elif defined(MAXHOSTNAMELEN)
#  define HOST_NAME_MAX MAXHOSTNAMELEN
# ಇಲ್ಲದಿದ್ದರೆ
#  define HOST_NAME_MAX	255
# endif
#ಆದರೆ_ಅಂತ್ಯ /* HOST_NAME_MAX */

#ಆದರೆ defined(HAVE_DECL_MAXSYMLINKS) && HAVE_DECL_MAXSYMLINKS == 0
# define MAXSYMLINKS 5
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ STDIN_FILENO
# define STDIN_FILENO    0
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ STDOUT_FILENO
# define STDOUT_FILENO   1
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ STDERR_FILENO
# define STDERR_FILENO   2
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ NGROUPS_MAX	/* Disable groupaccess if NGROUP_MAX is not set */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ NGROUPS
#ವ್ಯಾಖ್ಯಾನಿಸು NGROUPS_MAX NGROUPS
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿಸು NGROUPS_MAX 0
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_DECL_O_NONBLOCK) && HAVE_DECL_O_NONBLOCK == 0
# define O_NONBLOCK      00004	/* Non Blocking Open */
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ S_IFSOCK
# define S_IFSOCK 0
#ಆದರೆ_ಅಂತ್ಯ /* S_IFSOCK */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ S_ISDIR
# define S_ISDIR(ಬಹುಲಕ)	(((ಬಹುಲಕ) & (_S_IFMT)) == (_S_IFDIR))
#ಆದರೆ_ಅಂತ್ಯ /* S_ISDIR */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ S_ISREG
# define S_ISREG(ಬಹುಲಕ)	(((ಬಹುಲಕ) & (_S_IFMT)) == (_S_IFREG))
#ಆದರೆ_ಅಂತ್ಯ /* S_ISREG */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ S_ISLNK
# define S_ISLNK(ಬಹುಲಕ)	(((ಬಹುಲಕ) & S_IFMT) == S_IFLNK)
#ಆದರೆ_ಅಂತ್ಯ /* S_ISLNK */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ S_IXUSR
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
#ಆದರೆ_ಅಂತ್ಯ /* S_IXUSR */

#ಆದರೆ !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
#ವ್ಯಾಖ್ಯಾನಿಸು MAP_ANON MAP_ANONYMOUS
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ MAP_FAILED
# define MAP_FAILED ((ಶೂನ್ಯ *)-1)
#ಆದರೆ_ಅಂತ್ಯ

/*
SCO Open Server 3 has INADDR_LOOPBACK defined in rpc/rpc.h but
including rpc/rpc.h breaks Solaris 6
*/
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ INADDR_LOOPBACK
#ವ್ಯಾಖ್ಯಾನಿಸು INADDR_LOOPBACK ((u_long)0x7f000001)
#ಆದರೆ_ಅಂತ್ಯ

/* Types */

/* If sys/types.h does not supply intXX_t, supply them ourselves */
/* (or die trying) */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_U_INT
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಗಿಡ್ಡ u_short;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ u_int;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ u_long;
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_INTXX_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆಯುಳ್ಳ ಅಕ್ಷರ int8_t;
# ಆದರೆ (SIZEOF_SHORT_INT == 2)
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಗಿಡ್ಡ ಪೂರ್ಣಾಂಕ int16_t;
# ಇಲ್ಲದಿದ್ದರೆ
#   error "16 bit int type not found."
# endif
# ಆದರೆ (SIZEOF_INT == 4)
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಪೂರ್ಣಾಂಕ int32_t;
# ಇಲ್ಲದಿದ್ದರೆ
#   error "32 bit int type not found."
# endif
#ಆದರೆ_ಅಂತ್ಯ

/* If sys/types.h does not supply u_intXX_t, supply them ourselves */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_U_INTXX_T
# ifdef HAVE_UINTXX_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint8_t u_int8_t;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint16_t u_int16_t;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint32_t u_int32_t;
# define HAVE_U_INTXX_T 1
# ಇಲ್ಲದಿದ್ದರೆ
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ u_int8_t;
#  ಆದರೆ (SIZEOF_SHORT_INT == 2)
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಗಿಡ್ಡ ಪೂರ್ಣಾಂಕ u_int16_t;
#  ಇಲ್ಲದಿದ್ದರೆ
#    error "16 bit int type not found."
#  endif
#  ಆದರೆ (SIZEOF_INT == 4)
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ u_int32_t;
#  ಇಲ್ಲದಿದ್ದರೆ
#    error "32 bit int type not found."
#  endif
# endif
#ವ್ಯಾಖ್ಯಾನಿಸು __BIT_TYPES_DEFINED__
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(LLONG_MIN) && defined(LONG_LONG_MIN)
#ವ್ಯಾಖ್ಯಾನಿಸು LLONG_MIN LONG_LONG_MIN
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ !defined(LLONG_MAX) && defined(LONG_LONG_MAX)
#ವ್ಯಾಖ್ಯಾನಿಸು LLONG_MAX LONG_LONG_MAX
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ UINT32_MAX
# ಆದರೆ defined(HAVE_DECL_UINT32_MAX) && (HAVE_DECL_UINT32_MAX == 0)
#  ಆದರೆ (SIZEOF_INT == 4)
#    define UINT32_MAX	UINT_MAX
#  endif
# endif
#ಆದರೆ_ಅಂತ್ಯ

/* 64-bit types */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_INT64_T
# ಆದರೆ (SIZEOF_LONG_INT == 8)
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ದೀರ್ಘ ಪೂರ್ಣಾಂಕ int64_t;
# ಇಲ್ಲದಿದ್ದರೆ
#  ಆದರೆ (SIZEOF_LONG_LONG_INT == 8)
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ದೀರ್ಘ ದೀರ್ಘ ಪೂರ್ಣಾಂಕ int64_t;
#  endif
# endif
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_U_INT64_T
# ಆದರೆ (SIZEOF_LONG_INT == 8)
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಪೂರ್ಣಾಂಕ u_int64_t;
# ಇಲ್ಲದಿದ್ದರೆ
#  ಆದರೆ (SIZEOF_LONG_LONG_INT == 8)
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ ಪೂರ್ಣಾಂಕ u_int64_t;
#  endif
# endif
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_UINTXX_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ u_int8_t uint8_t;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ u_int16_t uint16_t;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ u_int32_t uint32_t;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ u_int64_t uint64_t;
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_INTMAX_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ದೀರ್ಘ ದೀರ್ಘ intmax_t;
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_UINTMAX_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ uintmax_t;
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ SIZEOF_ಸಮಯ_T == SIZEOF_LONG_LONG_INT
# define SSH_ಸಮಯ_T_MAX LLONG_MAX
#ಇಲ್ಲದಿದ್ದರೆ
# define SSH_ಸಮಯ_T_MAX ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_U_CHAR
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ u_char;
# define HAVE_U_CHAR
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_U_CHAR */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ULLONG_MAX
# define ULLONG_MAX ((ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)-1)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಗಾತ್ರ_T_MAX
#ವ್ಯಾಖ್ಯಾನಿಸು ಗಾತ್ರ_T_MAX ULONG_MAX
#ಆದರೆ_ಅಂತ್ಯ /* SIZE_T_MAX */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ಗಾತ್ರ_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ ಗಾತ್ರ_t;
# define HAVE_ಗಾತ್ರ_T
# define ಗಾತ್ರ_T_MAX UINT_MAX
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_SIZE_T */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SIZE_MAX
#ವ್ಯಾಖ್ಯಾನಿಸು SIZE_MAX ಗಾತ್ರ_T_MAX
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ INT32_MAX
# ಆದರೆ (SIZEOF_INT == 4)
#  define INT32_MAX ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ
# elif (SIZEOF_LONG == 4)
#  define INT32_MAX LONG_MAX
# ಇಲ್ಲದಿದ್ದರೆ
#  error "need INT32_MAX"
# endif
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ INT64_MAX
# ಆದರೆ (SIZEOF_INT == 8)
#  define INT64_MAX ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ
# elif (SIZEOF_LONG == 8)
#  define INT64_MAX LONG_MAX
# elif (SIZEOF_LONG_LONG_INT == 8)
#  define INT64_MAX LLONG_MAX
# ಇಲ್ಲದಿದ್ದರೆ
#  error "need INT64_MAX"
# endif
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SSIZE_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಪೂರ್ಣಾಂಕ ssize_t;
#ವ್ಯಾಖ್ಯಾನಿಸು SSIZE_MAX ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ
# define HAVE_SSIZE_T
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_SSIZE_T */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_CLOCK_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ದೀರ್ಘ clock_t;
# define HAVE_CLOCK_T
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_CLOCK_T */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SA_FAMILY_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಪೂರ್ಣಾಂಕ sa_family_t;
# define HAVE_SA_FAMILY_T
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_SA_FAMILY_T */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_PID_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಪೂರ್ಣಾಂಕ pid_t;
# define HAVE_PID_T
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_PID_T */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SIG_ATOMIC_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಪೂರ್ಣಾಂಕ sig_atomic_t;
# define HAVE_SIG_ATOMIC_T
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_SIG_ATOMIC_T */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ಬಹುಲಕ_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಪೂರ್ಣಾಂಕ ಬಹುಲಕ_t;
# define HAVE_ಬಹುಲಕ_T
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_MODE_T */

#ಆದರೆ !defined(HAVE_SS_FAMILY_ಒಳ_SS) && defined(HAVE_SS_FAMILY_ಒಳ_SS_2)
# define ss_family __ss_family
#ಆದರೆ_ಅಂತ್ಯ /* !defined(HAVE_SS_FAMILY_IN_SS) && defined(HAVE_SA_FAMILY_IN_SS) */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SYS_UN_H
ರಚನೆ	sockaddr_un {
	ಗಿಡ್ಡ	sun_family;		/* AF_UNIX */
	ಅಕ್ಷರ	sun_ಮಾರ್ಗ[108];		/* path name (gag) */
};
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_SYS_UN_H */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ಒಳ_ADDR_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ u_int32_t	in_addr_t;
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ಒಳ_ಪೋರ್ಟ್_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ u_int16_t	in_port_t;
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(BROKEN_SYS_TERMIO_H) && !defined(_STRUCT_WINSIZE)
#ವ್ಯಾಖ್ಯಾನಿಸು _STRUCT_WINSIZE
ರಚನೆ winsize {
      ಚಿಹ್ನೆರಹಿತ ಗಿಡ್ಡ ws_ಅಡ್ಡಸಾಲು;          /* rows, in characters */
      ಚಿಹ್ನೆರಹಿತ ಗಿಡ್ಡ ws_ಲಂಬಸಾಲು;          /* columns, in character */
      ಚಿಹ್ನೆರಹಿತ ಗಿಡ್ಡ ws_xpixel;       /* horizontal size, pixels */
      ಚಿಹ್ನೆರಹಿತ ಗಿಡ್ಡ ws_ypixel;       /* vertical size, pixels */
};
#ಆದರೆ_ಅಂತ್ಯ

/* bits needed for select that may not be in the system headers */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FD_ಮುಖವಾಡ
 ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಪೂರ್ಣಾಂಕ	fd_ಮುಖವಾಡ;
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_DECL_NFDBITS) && HAVE_DECL_NFDBITS == 0
# define	NFDBITS (8 * ಗಾತ್ರ(ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ))
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_DECL_HOWMANY) && HAVE_DECL_HOWMANY == 0
# define howmany(x,y)	(((x)+((y)-1))/(y))
#ಆದರೆ_ಅಂತ್ಯ

/* Paths */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _PATH_BSHELL
# define _PATH_BSHELL "/bin/sh"
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USER_ಮಾರ್ಗ
# ifdef _PATH_STDPATH
#  undef _PATH_STDPATH
# endif
# define _PATH_STDPATH USER_ಮಾರ್ಗ
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _PATH_STDPATH
# define _PATH_STDPATH "/usr/bin:/bin:/usr/sbin:/sbin"
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SUPERUSER_ಮಾರ್ಗ
# define SUPERUSER_ಮಾರ್ಗ	_PATH_STDPATH
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _PATH_DEVNULL
# define _PATH_DEVNULL "/dev/null"
#ಆದರೆ_ಅಂತ್ಯ

/* user may have set a different path */
#ಆದರೆ defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY)
# undef _PATH_MAILDIR
#ಆದರೆ_ಅಂತ್ಯ /* defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY) */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ MAIL_DIRECTORY
# define _PATH_MAILDIR MAIL_DIRECTORY
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _PATH_NOLOGIN
# define _PATH_NOLOGIN "/etc/nologin"
#ಆದರೆ_ಅಂತ್ಯ

/* Define this to be the path of the xauth program. */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ XAUTH_ಮಾರ್ಗ
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_XAUTH XAUTH_ಮಾರ್ಗ
#ಆದರೆ_ಅಂತ್ಯ /* XAUTH_PATH */

/* derived from XF4/xc/lib/dps/Xlibnet.h */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ X_UNIX_ಮಾರ್ಗ
#  ifdef __hpux
#    define X_UNIX_ಮಾರ್ಗ "/var/spool/sockets/X11/%u"
#  ಇಲ್ಲದಿದ್ದರೆ
#    define X_UNIX_ಮಾರ್ಗ "/tmp/.X11-unix/X%u"
#  endif
#ಆದರೆ_ಅಂತ್ಯ /* X_UNIX_PATH */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_UNIX_X X_UNIX_ಮಾರ್ಗ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _PATH_TTY
# define _PATH_TTY "/dev/tty"
#ಆದರೆ_ಅಂತ್ಯ

/* Macros */

#ಆದರೆ defined(HAVE_LOGIN_GETCAPBOOL) && defined(HAVE_LOGIN_CAP_H)
# define HAVE_LOGIN_CAP
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
# define MIN(a,b) (((a)<(b))?(a):(b))
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ roundup
# define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ timersub
#ವ್ಯಾಖ್ಯಾನಿಸು timersub(a, b, ಫಲಿತಾಂಶ)					\
   ಮಾಡು {								\
      (ಫಲಿತಾಂಶ)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
      (ಫಲಿತಾಂಶ)->tv_usec = (a)->tv_usec - (b)->tv_usec;		\
      ಆದರೆ ((ಫಲಿತಾಂಶ)->tv_usec < 0) {				\
	 --(ಫಲಿತಾಂಶ)->tv_sec;					\
	 (ಫಲಿತಾಂಶ)->tv_usec += 1000000;				\
      }								\
   } ಆಗ (0)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ timespeccmp
#ವ್ಯಾಖ್ಯಾನಿಸು	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ TIMEVAL_ಗಮ್ಯ_TIMESPEC
#ವ್ಯಾಖ್ಯಾನಿಸು	TIMEVAL_ಗಮ್ಯ_TIMESPEC(tv, ts) {					\
	(ts)->tv_sec = (tv)->tv_sec;					\
	(ts)->tv_nsec = (tv)->tv_usec * 1000;				\
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ TIMESPEC_ಗಮ್ಯ_TIMEVAL
#ವ್ಯಾಖ್ಯಾನಿಸು	TIMESPEC_ಗಮ್ಯ_TIMEVAL(tv, ts) {					\
	(tv)->tv_sec = (ts)->tv_sec;					\
	(tv)->tv_usec = (ts)->tv_nsec / 1000;				\
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ timespeccmp
#ವ್ಯಾಖ್ಯಾನಿಸು timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#ಆದರೆ_ಅಂತ್ಯ

/* Operations on timespecs. */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ timespecclear
#ವ್ಯಾಖ್ಯಾನಿಸು	timespecclear(tsp)		(tsp)->tv_sec = (tsp)->tv_nsec = 0
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ timespeccmp
#ವ್ಯಾಖ್ಯಾನಿಸು	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ timespecadd
#ವ್ಯಾಖ್ಯಾನಿಸು	timespecadd(tsp, usp, vsp)					\
	ಮಾಡು {								\
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;	\
		ಆದರೆ ((vsp)->tv_nsec >= 1000000000L) {			\
			(vsp)->tv_sec++;				\
			(vsp)->tv_nsec -= 1000000000L;			\
		}							\
	} ಆಗ (0)
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ timespecsub
#ವ್ಯಾಖ್ಯಾನಿಸು	timespecsub(tsp, usp, vsp)					\
	ಮಾಡು {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		ಆದರೆ ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} ಆಗ (0)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ __P
# define __P(x) x
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(IN6_IS_ADDR_V4MAPPED)
# define IN6_IS_ADDR_V4MAPPED(a) \
	((((u_int32_t *) (a))[0] == 0) && (((u_int32_t *) (a))[1] == 0) && \
	 (((u_int32_t *) (a))[2] == htonl (0xffff)))
#ಆದರೆ_ಅಂತ್ಯ /* !defined(IN6_IS_ADDR_V4MAPPED) */

#ಆದರೆ !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#ಆದರೆ_ಅಂತ್ಯ /* !defined(__GNUC__) || (__GNUC__ < 2) */

#ಆದರೆ !defined(HAVE_ATTRIBUTE__SENTINEL__) && !defined(__sentinel__)
# define __sentinel__
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__bounded__)
# define __bounded__(x, y, z)
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(HAVE_ATTRIBUTE__NONNULL__) && !defined(__nonnull__)
# define __nonnull__(x)
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(HAVE_ATTRIBUTE__NONSTRING__) && !defined(__nonstring__)
# define __nonstring__
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ OSSH_ALIGNBYTES
#ವ್ಯಾಖ್ಯಾನಿಸು OSSH_ALIGNBYTES	(ಗಾತ್ರ(ಪೂರ್ಣಾಂಕ) - 1)
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ __CMSG_ALIGN
#ವ್ಯಾಖ್ಯಾನಿಸು	__CMSG_ALIGN(p) (((u_int)(p) + OSSH_ALIGNBYTES) &~ OSSH_ALIGNBYTES)
#ಆದರೆ_ಅಂತ್ಯ

/* Length of the contents of a control message of length len */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ CMSG_LEN
#ವ್ಯಾಖ್ಯಾನಿಸು	CMSG_LEN(len)	(__CMSG_ALIGN(ಗಾತ್ರ(ರಚನೆ cmsghdr)) + (len))
#ಆದರೆ_ಅಂತ್ಯ

/* Length of the space taken up by a padded control message of length len */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ CMSG_SPACE
#ವ್ಯಾಖ್ಯಾನಿಸು	CMSG_SPACE(len)	(__CMSG_ALIGN(ಗಾತ್ರ(ರಚನೆ cmsghdr)) + __CMSG_ALIGN(len))
#ಆದರೆ_ಅಂತ್ಯ

/* given pointer to struct cmsghdr, return pointer to data */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ CMSG_DATA
#ವ್ಯಾಖ್ಯಾನಿಸು CMSG_DATA(cmsg) ((u_char *)(cmsg) + __CMSG_ALIGN(ಗಾತ್ರ(ರಚನೆ cmsghdr)))
#ಆದರೆ_ಅಂತ್ಯ /* CMSG_DATA */

/*
 * RFC 2292 requires to check msg_controllen, in case that the kernel returns
 * an empty list for some reasons.
 */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ CMSG_FIRSTHDR
#ವ್ಯಾಖ್ಯಾನಿಸು CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= ಗಾತ್ರ(ರಚನೆ cmsghdr) ? \
	 (ರಚನೆ cmsghdr *)(mhdr)->msg_control : \
	 (ರಚನೆ cmsghdr *)ಖಾಲಿ)
#ಆದರೆ_ಅಂತ್ಯ /* CMSG_FIRSTHDR */

#ಆದರೆ defined(HAVE_DECL_OFFSETOF) && HAVE_DECL_OFFSETOF == 0
# define offsetof(type, member) ((ಗಾತ್ರ_t) &((type *)0)->member)
#ಆದರೆ_ಅಂತ್ಯ

/* Set up BSD-style BYTE_ORDER definition if it isn't there already */
/* XXX: doesn't try to cope with strange byte orders (PDP_ENDIAN) */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ BYTE_ORDER
# ifndef LITTLE_ENDIAN
#  define LITTLE_ENDIAN  1234
# endif /* LITTLE_ENDIAN */
# ifndef BIG_ENDIAN
#  define BIG_ENDIAN     4321
# endif /* BIG_ENDIAN */
# ifdef ಪದಗಳು_BIGENDIAN
#  define BYTE_ORDER BIG_ENDIAN
# ಇಲ್ಲದಿದ್ದರೆ /* WORDS_BIGENDIAN */
#  define BYTE_ORDER LITTLE_ENDIAN
# endif /* WORDS_BIGENDIAN */
#ಆದರೆ_ಅಂತ್ಯ /* BYTE_ORDER */

#ಆದರೆ (defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0) || \
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
# ifdef ಪದಗಳು_BIGENDIAN
#  ಆದರೆ defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) (openssh_swap32(v))
#  endif
#  ಆದರೆ defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#   define le64toh(v) (openssh_swap64(v))
#  endif
#  ಆದರೆ defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) (openssh_swap64(v))
#  endif
#  ಆದರೆ defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) ((uint32_t)v)
#  endif
# ಇಲ್ಲದಿದ್ದರೆ
#  ಆದರೆ defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) ((uint32_t)v)
#  endif
#  ಆದರೆ defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#    define le64toh(v) ((uint64_t)v)
#  endif
#  ಆದರೆ defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) ((uint64_t)v)
#  endif
#  ಆದರೆ defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) (openssh_swap32(v))
#  endif
# endif
#ಆದರೆ_ಅಂತ್ಯ

/* Function replacement / compatibility hacks */

#ಆದರೆ !defined(HAVE_GETADDRINFO) && (defined(HAVE_OGETADDRINFO) || defined(HAVE_NGETADDRINFO))
# define HAVE_GETADDRINFO
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GETOPT_OPTRESET
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
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(BROKEN_GETADDRINFO) && defined(HAVE_GETADDRINFO)
# undef HAVE_GETADDRINFO
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(BROKEN_GETADDRINFO) && defined(HAVE_FREEADDRINFO)
# undef HAVE_FREEADDRINFO
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(BROKEN_GETADDRINFO) && defined(HAVE_GAI_STRERROR)
# undef HAVE_GAI_STRERROR
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_GETADDRINFO)
# ಆದರೆ defined(HAVE_DECL_AI_NUMERICSERV) && HAVE_DECL_AI_NUMERICSERV == 0
#   define AI_NUMERICSERV	0
# endif
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(BROKEN_UPDWTMPX) && defined(HAVE_UPDWTMPX)
# undef HAVE_UPDWTMPX
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(BROKEN_SHADOW_EXPIRE) && defined(HAS_SHADOW_EXPIRE)
# undef HAS_SHADOW_EXPIRE
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_OPENLOG_R) && defined(SYSLOG_ದತ್ತಾಂಶ_INIT) && \
    defined(SYSLOG_R_ಸುರಕ್ಷಿತ_ಒಳ_SIGHAND)
# define DO_LOG_ಸುರಕ್ಷಿತ_ಒಳ_SIGHAND
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY)
# define memmove(s1, s2, n) bcopy((s2), (s1), (n))
#ಆದರೆ_ಅಂತ್ಯ /* !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY) */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ GETPGRP_VOID
# include <unistd.h>
# define getpgrp() getpgrp(0)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_BSM_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LINUX_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(HAVE___func__) && defined(HAVE___FUNCTION__)
#  define __func__ __FUNCTION__
#ಅಥವಾಆದರೆ !defined(HAVE___func__)
#  define __func__ ""
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(KRB5) && !defined(HEIMDAL)
#  define krb5_get_err_ಪಠ್ಯ(context,ಸಂಕೇತ_2) error_ಸಂದೇಶ(ಸಂಕೇತ_2)
#ಆದರೆ_ಅಂತ್ಯ

/* Maximum number of file descriptors available */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYSCONF
# define SSH_SYSFDMAX sysconf(_SC_OPEN_MAX)
#ಇಲ್ಲದಿದ್ದರೆ
# define SSH_SYSFDMAX 10000
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ FSID_HAS_VAL
/* encode f_fsid into a 64 bit value  */
#ವ್ಯಾಖ್ಯಾನಿಸು FSID_ಗಮ್ಯ_ULONG(f) \
	((((u_int64_t)(f).val[0] & 0xffffffffUL) << 32) | \
	    ((f).val[1] & 0xffffffffUL))
#ಅಥವಾಆದರೆ defined(FSID_HAS___VAL)
#ವ್ಯಾಖ್ಯಾನಿಸು FSID_ಗಮ್ಯ_ULONG(f) \
	((((u_int64_t)(f).__val[0] & 0xffffffffUL) << 32) | \
	    ((f).__val[1] & 0xffffffffUL))
#ಇಲ್ಲದಿದ್ದರೆ
# define FSID_ಗಮ್ಯ_ULONG(f) ((f))
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(__Lynx__)
 /*
  * LynxOS defines these in param.h which we do not want to include since
  * it will also pull in a bunch of kernel definitions.
  */
# define ALIGNBYTES (ಗಾತ್ರ(ಪೂರ್ಣಾಂಕ) - 1)
# define ALIGN(p) (((ಚಿಹ್ನೆರಹಿತ)p + ALIGNBYTES) & ~ALIGNBYTES)
  /* Missing prototypes on LynxOS */
  ಪೂರ್ಣಾಂಕ snprintf (ಅಕ್ಷರ *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...);
  ಪೂರ್ಣಾಂಕ mkstemp (ಅಕ್ಷರ *);
  ಅಕ್ಷರ *crypt (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
  ಪೂರ್ಣಾಂಕ seteuid (uid_t);
  ಪೂರ್ಣಾಂಕ setegid (gid_t);
  ಅಕ್ಷರ *mkdtemp (ಅಕ್ಷರ *);
  ಪೂರ್ಣಾಂಕ rresvport_af (ಪೂರ್ಣಾಂಕ *, sa_family_t);
  ಪೂರ್ಣಾಂಕ innetgr (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
#ಆದರೆ_ಅಂತ್ಯ

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
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ UTMP_FILE
#  ifdef _PATH_UTMP
#    define UTMP_FILE _PATH_UTMP
#  ಇಲ್ಲದಿದ್ದರೆ
#    ifdef CONF_UTMP_FILE
#      define UTMP_FILE CONF_UTMP_FILE
#    endif
#  endif
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ WTMP_FILE
#  ifdef _PATH_WTMP
#    define WTMP_FILE _PATH_WTMP
#  ಇಲ್ಲದಿದ್ದರೆ
#    ifdef CONF_WTMP_FILE
#      define WTMP_FILE CONF_WTMP_FILE
#    endif
#  endif
#ಆದರೆ_ಅಂತ್ಯ
/* pick up the user's location for lastlog if given */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ LASTLOG_FILE
#  ifdef _PATH_LASTLOG
#    define LASTLOG_FILE _PATH_LASTLOG
#  ಇಲ್ಲದಿದ್ದರೆ
#    ifdef CONF_LASTLOG_FILE
#      define LASTLOG_FILE CONF_LASTLOG_FILE
#    endif
#  endif
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
# define USE_SHADOW
#ಆದರೆ_ಅಂತ್ಯ

/* The login() library function in libutil is first choice */
#ಆದರೆ defined(HAVE_LOGIN) && !defined(DISABLE_LOGIN)
#  define USE_LOGIN

#ಇಲ್ಲದಿದ್ದರೆ
/* Simply select your favourite login types. */
/* Can't do if-else because some systems use several... <sigh> */
#  ಆದರೆ !defined(DISABLE_UTMPX)
#    define USE_UTMPX
#  endif
#  ಆದರೆ defined(UTMP_FILE) && !defined(DISABLE_UTMP)
#    define USE_UTMP
#  endif
#  ಆದರೆ defined(WTMPX_FILE) && !defined(DISABLE_WTMPX)
#    define USE_WTMPX
#  endif
#  ಆದರೆ defined(WTMP_FILE) && !defined(DISABLE_WTMP)
#    define USE_WTMP
#  endif

#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ UT_LINESIZE
# define UT_LINESIZE 8
#ಆದರೆ_ಅಂತ್ಯ

/* I hope that the presence of LASTLOG_FILE is enough to detect this */
#ಆದರೆ defined(LASTLOG_FILE) && !defined(DISABLE_LASTLOG)
#  define USE_LASTLOG
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_OSF_SIA
# ifdef USE_SHADOW
#  undef USE_SHADOW
# endif
# define CUSTOM_SYS_AUTH_PASSWD 1
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_LIBIAF) && defined(HAVE_ಗಣ_ID) && !defined(HAVE_SECUREWARE)
# define CUSTOM_SYS_AUTH_PASSWD 1
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(HAVE_LIBIAF) && defined(HAVE_ಗಣ_ID) && !defined(BROKEN_LIBIAF)
# define USE_LIBIAF
#ಆದರೆ_ಅಂತ್ಯ

/* HP-UX 11.11 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BTMP_FILE
# define ಮಾರ್ಗ_BTMP BTMP_FILE
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(USE_BTMP) && defined(ಮಾರ್ಗ_BTMP)
# define CUSTOM_FAILED_LOGIN
#ಆದರೆ_ಅಂತ್ಯ

/** end of login recorder definitions */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BROKEN_GETGROUPS
# define getgroups(a,b) ((a)==0 && (b)==ಖಾಲಿ ? NGROUPS_MAX : getgroups((a),(b)))
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ IOV_MAX
# ಆದರೆ defined(_XOPEN_IOV_MAX)
#  define	IOV_MAX		_XOPEN_IOV_MAX
# elif defined(DEF_IOV_MAX)
#  define	IOV_MAX		DEF_IOV_MAX
# ಇಲ್ಲದಿದ್ದರೆ
#  define	IOV_MAX		16
# endif
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ EWOULDBLOCK
# define EWOULDBLOCK EAGAIN
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ INET6_ADDRSTRLEN	/* for non IPv6 machines */
#ವ್ಯಾಖ್ಯಾನಿಸು INET6_ADDRSTRLEN 46
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SSH_IOBUFSZ
# define SSH_IOBUFSZ 8192
#ಆದರೆ_ಅಂತ್ಯ

/*
 * We want functions in openbsd-compat, if enabled, to override system ones.
 * We no-op out the weak symbol definition rather than remove it to reduce
 * future sync problems.  Some compilers (eg Unixware) do not allow an
 * empty statement, so we use a bogus function declaration.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು DEF_WEAK(x)	ಶೂನ್ಯ __ssh_compat_weak_##x(ಶೂನ್ಯ)

/*
 * Platforms that have arc4random_uniform() and not arc4random_stir()
 * shouldn't need the latter.
 */
#ಆದರೆ defined(HAVE_ARC4RANDOM) && defined(HAVE_ARC4_RANDOM_ಏಕರೂಪ) && \
    !defined(HAVE_ARC4RANDOM_STIR)
# define arc4random_stir()
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_VA_COPY
# ifdef HAVE___VA_COPY
#  define va_copy(dest, src) __va_copy(dest, src)
# ಇಲ್ಲದಿದ್ದರೆ
#  define va_copy(dest, src) (dest) = (src)
# endif
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ __predict_true
# ಆದರೆ defined(__GNUC__) && \
     ((__GNUC__ > (2)) || (__GNUC__ == (2) && __GNUC_MINOR__ >= (96)))
#  define __predict_true(ಘಾತಾಂಕ)     __builtin_expect(((ಘಾತಾಂಕ) != 0), 1)
#  define __predict_false(ಘಾತಾಂಕ)    __builtin_expect(((ಘಾತಾಂಕ) != 0), 0)
# ಇಲ್ಲದಿದ್ದರೆ
#  define __predict_true(ಘಾತಾಂಕ)     ((ಘಾತಾಂಕ) != 0)
#  define __predict_false(ಘಾತಾಂಕ)    ((ಘಾತಾಂಕ) != 0)
# endif /* gcc version */
#ಆದರೆ_ಅಂತ್ಯ /* __predict_true */

/*
 * sntrup761 uses variable length arrays and c99-style declarations after code,
 * so only enable if the compiler supports them.
 */
#ಆದರೆ defined(VARIABLE_ಉದ್ದಳತೆ_ARRAYS) && defined(VARIABLE_DECLARATION_AFTER_ಸಂಕೇತ)
# define USE_SNTRUP761X25519	1
/* The ML-KEM768 and ML-DSA implementations also uses C89 features */
# define USE_MLKEM768X25519	1
# define USE_MLDSA		1
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_DECL_INFINITY) && HAVE_DECL_INFINITY == 0
# ಆದರೆ defined(HAVE_DECL___BUILTIN_INFF) && HAVE_DECL___BUILTIN_INFF == 1
#  define INFINITY __builtin_inff()
# endif
#ಆದರೆ_ಅಂತ್ಯ

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
#ಆದರೆ defined(DISABLE_FD_PASSING) && !defined(HAVE_CYGWIN)
# define SKIP_PRIVDROP 1
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ /* _DEFINES_H */
