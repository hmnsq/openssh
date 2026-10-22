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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਨਿਰਧਾਰਤ_ਕਰਦਾ_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਨਿਰਧਾਰਤ_ਕਰਦਾ_H

/* Constants */

#ਜੇ defined(HAVE_DECL_SHUT_RD) && HAVE_DECL_SHUT_RD == 0
ਗਿਣਤੀ
{
  SHUT_RD = 0,		/* No more receptions.  */
  SHUT_WR,			/* No more transmissions.  */
  SHUT_RDWR			/* No more receptions or transmissions.  */
};
# define SHUT_RD   SHUT_RD
# define SHUT_WR   SHUT_WR
# define SHUT_RDWR SHUT_RDWR
#ਜੇ_ਅੰਤ

/*
 * Cygwin doesn't really have a notion of reserved ports.  It is still
 * is useful on the client side so for compatibility it defines as 1024 via
 * netinet/in.h inside an enum.  We * don't actually want that restriction
 * so we want to set that to zero, but we can't do it direct in config.h
 * because it'll cause a conflicting definition the first time we include
 * netinet/in.h.
 */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ IPPORT_RESERVED 0
#ਜੇ_ਅੰਤ

/*
 * Definitions for IP type of service (ip_tos)
 */
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/ip.h>
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ IPTOS_LOWDELAY
# define IPTOS_LOWDELAY          0x10
# define IPTOS_THROUGHPUT        0x08
# define IPTOS_RELIABILITY       0x04
# define IPTOS_LOWCOST           0x02
# define IPTOS_MINCOST           IPTOS_LOWCOST
#ਜੇ_ਅੰਤ /* IPTOS_LOWDELAY */

/*
 * Definitions for DiffServ Codepoints as per RFCs 2474, 3246, 4594 & 8622.
 * These are the 6 most significant bits as they appear on the wire, so the
 * two least significant bits must be zero.
 */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ IPTOS_DSCP_AF11
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
#ਜੇ_ਅੰਤ /* IPTOS_DSCP_AF11 */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ IPTOS_DSCP_CS0
# define	IPTOS_DSCP_CS0		0x00
# define	IPTOS_DSCP_CS1		0x20
# define	IPTOS_DSCP_CS2		0x40
# define	IPTOS_DSCP_CS3		0x60
# define	IPTOS_DSCP_CS4		0x80
# define	IPTOS_DSCP_CS5		0xa0
# define	IPTOS_DSCP_CS6		0xc0
# define	IPTOS_DSCP_CS7		0xe0
#ਜੇ_ਅੰਤ /* IPTOS_DSCP_CS0 */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ IPTOS_DSCP_VA
# define	IPTOS_DSCP_VA		0xb0
#ਜੇ_ਅੰਤ /* IPTOS_DSCP_VA */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ IPTOS_DSCP_EF
# define	IPTOS_DSCP_EF		0xb8
#ਜੇ_ਅੰਤ /* IPTOS_DSCP_EF */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ IPTOS_DSCP_LE
# define	IPTOS_DSCP_LE		0x04
#ਜੇ_ਅੰਤ /* IPTOS_DSCP_LE */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ IPTOS_PREC_CRITIC_ECP
# define IPTOS_PREC_CRITIC_ECP		0xa0
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ IPTOS_PREC_INTERNETCONTROL
# define IPTOS_PREC_INTERNETCONTROL	0xc0
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ IPTOS_PREC_NETCONTROL
# define IPTOS_PREC_NETCONTROL		0xe0
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ PATH_MAX
# ifdef _POSIX_PATH_MAX
# define PATH_MAX _POSIX_PATH_MAX
# endif
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ MAXPATHLEN
# ifdef PATH_MAX
#  define MAXPATHLEN PATH_MAX
# ਨਹੀਂਤਾਂ /* PATH_MAX */
#  define MAXPATHLEN 64
# endif /* PATH_MAX */
#ਜੇ_ਅੰਤ /* MAXPATHLEN */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HOST_NAME_MAX
# include "netdb.h" /* for MAXHOSTNAMELEN */
# ਜੇ defined(_POSIX_HOST_NAME_MAX)
#  define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# elif defined(MAXHOSTNAMELEN)
#  define HOST_NAME_MAX MAXHOSTNAMELEN
# ਨਹੀਂਤਾਂ
#  define HOST_NAME_MAX	255
# endif
#ਜੇ_ਅੰਤ /* HOST_NAME_MAX */

#ਜੇ defined(HAVE_DECL_MAXSYMLINKS) && HAVE_DECL_MAXSYMLINKS == 0
# define MAXSYMLINKS 5
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ STDIN_FILENO
# define STDIN_FILENO    0
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ STDOUT_FILENO
# define STDOUT_FILENO   1
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ STDERR_FILENO
# define STDERR_FILENO   2
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ NGROUPS_MAX	/* Disable groupaccess if NGROUP_MAX is not set */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ NGROUPS
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NGROUPS_MAX NGROUPS
#ਨਹੀਂਤਾਂ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NGROUPS_MAX 0
#ਜੇ_ਅੰਤ
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_DECL_O_NONBLOCK) && HAVE_DECL_O_NONBLOCK == 0
# define O_NONBLOCK      00004	/* Non Blocking Open */
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ S_IFSOCK
# define S_IFSOCK 0
#ਜੇ_ਅੰਤ /* S_IFSOCK */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ S_ISDIR
# define S_ISDIR(ਬਹੁਲਕ)	(((ਬਹੁਲਕ) & (_S_IFMT)) == (_S_IFDIR))
#ਜੇ_ਅੰਤ /* S_ISDIR */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ S_ISREG
# define S_ISREG(ਬਹੁਲਕ)	(((ਬਹੁਲਕ) & (_S_IFMT)) == (_S_IFREG))
#ਜੇ_ਅੰਤ /* S_ISREG */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ S_ISLNK
# define S_ISLNK(ਬਹੁਲਕ)	(((ਬਹੁਲਕ) & S_IFMT) == S_IFLNK)
#ਜੇ_ਅੰਤ /* S_ISLNK */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ S_IXUSR
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
#ਜੇ_ਅੰਤ /* S_IXUSR */

#ਜੇ !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAP_ANON MAP_ANONYMOUS
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ MAP_FAILED
# define MAP_FAILED ((ਖਾਲੀ *)-1)
#ਜੇ_ਅੰਤ

/*
SCO Open Server 3 has INADDR_LOOPBACK defined in rpc/rpc.h but
including rpc/rpc.h breaks Solaris 6
*/
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ INADDR_LOOPBACK
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ INADDR_LOOPBACK ((u_long)0x7f000001)
#ਜੇ_ਅੰਤ

/* Types */

/* If sys/types.h does not supply intXX_t, supply them ourselves */
/* (or die trying) */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_U_INT
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਛੋਟਾ u_short;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ u_int;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ u_long;
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_INTXX_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਨਿਸ਼ਾਨੀਵਾਲਾ ਅੱਖਰ int8_t;
# ਜੇ (SIZEOF_SHORT_INT == 2)
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਛੋਟਾ ਪੂਰਨ int16_t;
# ਨਹੀਂਤਾਂ
#   error "16 bit int type not found."
# endif
# ਜੇ (SIZEOF_INT == 4)
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਪੂਰਨ int32_t;
# ਨਹੀਂਤਾਂ
#   error "32 bit int type not found."
# endif
#ਜੇ_ਅੰਤ

/* If sys/types.h does not supply u_intXX_t, supply them ourselves */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_U_INTXX_T
# ifdef HAVE_UINTXX_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ uint8_t u_int8_t;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ uint16_t u_int16_t;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ uint32_t u_int32_t;
# define HAVE_U_INTXX_T 1
# ਨਹੀਂਤਾਂ
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ u_int8_t;
#  ਜੇ (SIZEOF_SHORT_INT == 2)
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਛੋਟਾ ਪੂਰਨ u_int16_t;
#  ਨਹੀਂਤਾਂ
#    error "16 bit int type not found."
#  endif
#  ਜੇ (SIZEOF_INT == 4)
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ u_int32_t;
#  ਨਹੀਂਤਾਂ
#    error "32 bit int type not found."
#  endif
# endif
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ __BIT_TYPES_DEFINED__
#ਜੇ_ਅੰਤ

#ਜੇ !defined(LLONG_MIN) && defined(LONG_LONG_MIN)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LLONG_MIN LONG_LONG_MIN
#ਜੇ_ਅੰਤ
#ਜੇ !defined(LLONG_MAX) && defined(LONG_LONG_MAX)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LLONG_MAX LONG_LONG_MAX
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ UINT32_MAX
# ਜੇ defined(HAVE_DECL_UINT32_MAX) && (HAVE_DECL_UINT32_MAX == 0)
#  ਜੇ (SIZEOF_INT == 4)
#    define UINT32_MAX	UINT_MAX
#  endif
# endif
#ਜੇ_ਅੰਤ

/* 64-bit types */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_INT64_T
# ਜੇ (SIZEOF_LONG_INT == 8)
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਲੰਮਾ ਪੂਰਨ int64_t;
# ਨਹੀਂਤਾਂ
#  ਜੇ (SIZEOF_LONG_LONG_INT == 8)
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਲੰਮਾ ਲੰਮਾ ਪੂਰਨ int64_t;
#  endif
# endif
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_U_INT64_T
# ਜੇ (SIZEOF_LONG_INT == 8)
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਪੂਰਨ u_int64_t;
# ਨਹੀਂਤਾਂ
#  ਜੇ (SIZEOF_LONG_LONG_INT == 8)
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ ਪੂਰਨ u_int64_t;
#  endif
# endif
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_UINTXX_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ u_int8_t uint8_t;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ u_int16_t uint16_t;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ u_int32_t uint32_t;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ u_int64_t uint64_t;
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_INTMAX_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਲੰਮਾ ਲੰਮਾ intmax_t;
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_UINTMAX_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ uintmax_t;
#ਜੇ_ਅੰਤ

#ਜੇ SIZEOF_ਸਮਾਂ_T == SIZEOF_LONG_LONG_INT
# define SSH_ਸਮਾਂ_T_MAX LLONG_MAX
#ਨਹੀਂਤਾਂ
# define SSH_ਸਮਾਂ_T_MAX ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_U_CHAR
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ u_char;
# define HAVE_U_CHAR
#ਜੇ_ਅੰਤ /* HAVE_U_CHAR */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ULLONG_MAX
# define ULLONG_MAX ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)-1)
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਮਾਪ_T_MAX
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਮਾਪ_T_MAX ULONG_MAX
#ਜੇ_ਅੰਤ /* SIZE_T_MAX */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ਮਾਪ_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ ਮਾਪ_t;
# define HAVE_ਮਾਪ_T
# define ਮਾਪ_T_MAX UINT_MAX
#ਜੇ_ਅੰਤ /* HAVE_SIZE_T */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SIZE_MAX
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SIZE_MAX ਮਾਪ_T_MAX
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ INT32_MAX
# ਜੇ (SIZEOF_INT == 4)
#  define INT32_MAX ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ
# elif (SIZEOF_LONG == 4)
#  define INT32_MAX LONG_MAX
# ਨਹੀਂਤਾਂ
#  error "need INT32_MAX"
# endif
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ INT64_MAX
# ਜੇ (SIZEOF_INT == 8)
#  define INT64_MAX ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ
# elif (SIZEOF_LONG == 8)
#  define INT64_MAX LONG_MAX
# elif (SIZEOF_LONG_LONG_INT == 8)
#  define INT64_MAX LLONG_MAX
# ਨਹੀਂਤਾਂ
#  error "need INT64_MAX"
# endif
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SSIZE_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਪੂਰਨ ssize_t;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSIZE_MAX ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ
# define HAVE_SSIZE_T
#ਜੇ_ਅੰਤ /* HAVE_SSIZE_T */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_CLOCK_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਲੰਮਾ clock_t;
# define HAVE_CLOCK_T
#ਜੇ_ਅੰਤ /* HAVE_CLOCK_T */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SA_FAMILY_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਪੂਰਨ sa_family_t;
# define HAVE_SA_FAMILY_T
#ਜੇ_ਅੰਤ /* HAVE_SA_FAMILY_T */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_PID_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਪੂਰਨ pid_t;
# define HAVE_PID_T
#ਜੇ_ਅੰਤ /* HAVE_PID_T */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SIG_ATOMIC_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਪੂਰਨ sig_atomic_t;
# define HAVE_SIG_ATOMIC_T
#ਜੇ_ਅੰਤ /* HAVE_SIG_ATOMIC_T */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ਬਹੁਲਕ_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਪੂਰਨ ਬਹੁਲਕ_t;
# define HAVE_ਬਹੁਲਕ_T
#ਜੇ_ਅੰਤ /* HAVE_MODE_T */

#ਜੇ !defined(HAVE_SS_FAMILY_ਵਿੱਚ_SS) && defined(HAVE_SS_FAMILY_ਵਿੱਚ_SS_2)
# define ss_family __ss_family
#ਜੇ_ਅੰਤ /* !defined(HAVE_SS_FAMILY_IN_SS) && defined(HAVE_SA_FAMILY_IN_SS) */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_UN_H
ਬਣਤਰ	sockaddr_un {
	ਛੋਟਾ	sun_family;		/* AF_UNIX */
	ਅੱਖਰ	sun_ਰਸਤਾ[108];		/* path name (gag) */
};
#ਜੇ_ਅੰਤ /* HAVE_SYS_UN_H */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ਵਿੱਚ_ADDR_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ u_int32_t	in_addr_t;
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ਵਿੱਚ_ਪੋਰਟ_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ u_int16_t	in_port_t;
#ਜੇ_ਅੰਤ

#ਜੇ defined(BROKEN_SYS_TERMIO_H) && !defined(_STRUCT_WINSIZE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _STRUCT_WINSIZE
ਬਣਤਰ winsize {
      ਬਿਨਾਨਿਸ਼ਾਨੀ ਛੋਟਾ ws_ਪੰਕਤੀ;          /* rows, in characters */
      ਬਿਨਾਨਿਸ਼ਾਨੀ ਛੋਟਾ ws_ਖਾਨਾ;          /* columns, in character */
      ਬਿਨਾਨਿਸ਼ਾਨੀ ਛੋਟਾ ws_xpixel;       /* horizontal size, pixels */
      ਬਿਨਾਨਿਸ਼ਾਨੀ ਛੋਟਾ ws_ypixel;       /* vertical size, pixels */
};
#ਜੇ_ਅੰਤ

/* bits needed for select that may not be in the system headers */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FD_ਨਕਾਬ
 ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਪੂਰਨ	fd_ਨਕਾਬ;
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_DECL_NFDBITS) && HAVE_DECL_NFDBITS == 0
# define	NFDBITS (8 * ਆਕਾਰ(ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ))
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_DECL_HOWMANY) && HAVE_DECL_HOWMANY == 0
# define howmany(x,y)	(((x)+((y)-1))/(y))
#ਜੇ_ਅੰਤ

/* Paths */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _PATH_BSHELL
# define _PATH_BSHELL "/bin/sh"
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USER_ਰਸਤਾ
# ifdef _PATH_STDPATH
#  undef _PATH_STDPATH
# endif
# define _PATH_STDPATH USER_ਰਸਤਾ
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _PATH_STDPATH
# define _PATH_STDPATH "/usr/bin:/bin:/usr/sbin:/sbin"
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SUPERUSER_ਰਸਤਾ
# define SUPERUSER_ਰਸਤਾ	_PATH_STDPATH
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _PATH_DEVNULL
# define _PATH_DEVNULL "/dev/null"
#ਜੇ_ਅੰਤ

/* user may have set a different path */
#ਜੇ defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY)
# undef _PATH_MAILDIR
#ਜੇ_ਅੰਤ /* defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY) */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ MAIL_DIRECTORY
# define _PATH_MAILDIR MAIL_DIRECTORY
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _PATH_NOLOGIN
# define _PATH_NOLOGIN "/etc/nologin"
#ਜੇ_ਅੰਤ

/* Define this to be the path of the xauth program. */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ XAUTH_ਰਸਤਾ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_XAUTH XAUTH_ਰਸਤਾ
#ਜੇ_ਅੰਤ /* XAUTH_PATH */

/* derived from XF4/xc/lib/dps/Xlibnet.h */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ X_UNIX_ਰਸਤਾ
#  ifdef __hpux
#    define X_UNIX_ਰਸਤਾ "/var/spool/sockets/X11/%u"
#  ਨਹੀਂਤਾਂ
#    define X_UNIX_ਰਸਤਾ "/tmp/.X11-unix/X%u"
#  endif
#ਜੇ_ਅੰਤ /* X_UNIX_PATH */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_UNIX_X X_UNIX_ਰਸਤਾ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _PATH_TTY
# define _PATH_TTY "/dev/tty"
#ਜੇ_ਅੰਤ

/* Macros */

#ਜੇ defined(HAVE_LOGIN_GETCAPBOOL) && defined(HAVE_LOGIN_CAP_H)
# define HAVE_LOGIN_CAP
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
# define MIN(a,b) (((a)<(b))?(a):(b))
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ roundup
# define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ timersub
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ timersub(a, b, ਨਤੀਜਾ)					\
   ਕਰੋ {								\
      (ਨਤੀਜਾ)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
      (ਨਤੀਜਾ)->tv_usec = (a)->tv_usec - (b)->tv_usec;		\
      ਜੇ ((ਨਤੀਜਾ)->tv_usec < 0) {				\
	 --(ਨਤੀਜਾ)->tv_sec;					\
	 (ਨਤੀਜਾ)->tv_usec += 1000000;				\
      }								\
   } ਜਦੋਂ (0)
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ timespeccmp
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ TIMEVAL_ਮੰਜ਼ਿਲ_TIMESPEC
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	TIMEVAL_ਮੰਜ਼ਿਲ_TIMESPEC(tv, ts) {					\
	(ts)->tv_sec = (tv)->tv_sec;					\
	(ts)->tv_nsec = (tv)->tv_usec * 1000;				\
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ TIMESPEC_ਮੰਜ਼ਿਲ_TIMEVAL
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	TIMESPEC_ਮੰਜ਼ਿਲ_TIMEVAL(tv, ts) {					\
	(tv)->tv_sec = (ts)->tv_sec;					\
	(tv)->tv_usec = (ts)->tv_nsec / 1000;				\
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ timespeccmp
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#ਜੇ_ਅੰਤ

/* Operations on timespecs. */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ timespecclear
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	timespecclear(tsp)		(tsp)->tv_sec = (tsp)->tv_nsec = 0
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ timespeccmp
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ timespecadd
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	timespecadd(tsp, usp, vsp)					\
	ਕਰੋ {								\
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;	\
		ਜੇ ((vsp)->tv_nsec >= 1000000000L) {			\
			(vsp)->tv_sec++;				\
			(vsp)->tv_nsec -= 1000000000L;			\
		}							\
	} ਜਦੋਂ (0)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ timespecsub
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	timespecsub(tsp, usp, vsp)					\
	ਕਰੋ {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		ਜੇ ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} ਜਦੋਂ (0)
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ __P
# define __P(x) x
#ਜੇ_ਅੰਤ

#ਜੇ !defined(IN6_IS_ADDR_V4MAPPED)
# define IN6_IS_ADDR_V4MAPPED(a) \
	((((u_int32_t *) (a))[0] == 0) && (((u_int32_t *) (a))[1] == 0) && \
	 (((u_int32_t *) (a))[2] == htonl (0xffff)))
#ਜੇ_ਅੰਤ /* !defined(IN6_IS_ADDR_V4MAPPED) */

#ਜੇ !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#ਜੇ_ਅੰਤ /* !defined(__GNUC__) || (__GNUC__ < 2) */

#ਜੇ !defined(HAVE_ATTRIBUTE__SENTINEL__) && !defined(__sentinel__)
# define __sentinel__
#ਜੇ_ਅੰਤ

#ਜੇ !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__bounded__)
# define __bounded__(x, y, z)
#ਜੇ_ਅੰਤ

#ਜੇ !defined(HAVE_ATTRIBUTE__NONNULL__) && !defined(__nonnull__)
# define __nonnull__(x)
#ਜੇ_ਅੰਤ

#ਜੇ !defined(HAVE_ATTRIBUTE__NONSTRING__) && !defined(__nonstring__)
# define __nonstring__
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ OSSH_ALIGNBYTES
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ OSSH_ALIGNBYTES	(ਆਕਾਰ(ਪੂਰਨ) - 1)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ __CMSG_ALIGN
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	__CMSG_ALIGN(p) (((u_int)(p) + OSSH_ALIGNBYTES) &~ OSSH_ALIGNBYTES)
#ਜੇ_ਅੰਤ

/* Length of the contents of a control message of length len */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ CMSG_LEN
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	CMSG_LEN(len)	(__CMSG_ALIGN(ਆਕਾਰ(ਬਣਤਰ cmsghdr)) + (len))
#ਜੇ_ਅੰਤ

/* Length of the space taken up by a padded control message of length len */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ CMSG_SPACE
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	CMSG_SPACE(len)	(__CMSG_ALIGN(ਆਕਾਰ(ਬਣਤਰ cmsghdr)) + __CMSG_ALIGN(len))
#ਜੇ_ਅੰਤ

/* given pointer to struct cmsghdr, return pointer to data */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ CMSG_DATA
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CMSG_DATA(cmsg) ((u_char *)(cmsg) + __CMSG_ALIGN(ਆਕਾਰ(ਬਣਤਰ cmsghdr)))
#ਜੇ_ਅੰਤ /* CMSG_DATA */

/*
 * RFC 2292 requires to check msg_controllen, in case that the kernel returns
 * an empty list for some reasons.
 */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ CMSG_FIRSTHDR
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= ਆਕਾਰ(ਬਣਤਰ cmsghdr) ? \
	 (ਬਣਤਰ cmsghdr *)(mhdr)->msg_control : \
	 (ਬਣਤਰ cmsghdr *)ਨਿਰਾ)
#ਜੇ_ਅੰਤ /* CMSG_FIRSTHDR */

#ਜੇ defined(HAVE_DECL_OFFSETOF) && HAVE_DECL_OFFSETOF == 0
# define offsetof(type, member) ((ਮਾਪ_t) &((type *)0)->member)
#ਜੇ_ਅੰਤ

/* Set up BSD-style BYTE_ORDER definition if it isn't there already */
/* XXX: doesn't try to cope with strange byte orders (PDP_ENDIAN) */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ BYTE_ORDER
# ifndef LITTLE_ENDIAN
#  define LITTLE_ENDIAN  1234
# endif /* LITTLE_ENDIAN */
# ifndef BIG_ENDIAN
#  define BIG_ENDIAN     4321
# endif /* BIG_ENDIAN */
# ifdef ਸ਼ਬਦ_BIGENDIAN
#  define BYTE_ORDER BIG_ENDIAN
# ਨਹੀਂਤਾਂ /* WORDS_BIGENDIAN */
#  define BYTE_ORDER LITTLE_ENDIAN
# endif /* WORDS_BIGENDIAN */
#ਜੇ_ਅੰਤ /* BYTE_ORDER */

#ਜੇ (defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0) || \
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
# ifdef ਸ਼ਬਦ_BIGENDIAN
#  ਜੇ defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) (openssh_swap32(v))
#  endif
#  ਜੇ defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#   define le64toh(v) (openssh_swap64(v))
#  endif
#  ਜੇ defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) (openssh_swap64(v))
#  endif
#  ਜੇ defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) ((uint32_t)v)
#  endif
# ਨਹੀਂਤਾਂ
#  ਜੇ defined(HAVE_DECL_LE32TOH) && HAVE_DECL_LE32TOH == 0
#   define le32toh(v) ((uint32_t)v)
#  endif
#  ਜੇ defined(HAVE_DECL_LE64TOH) && HAVE_DECL_LE64TOH == 0
#    define le64toh(v) ((uint64_t)v)
#  endif
#  ਜੇ defined(HAVE_DECL_HTOLE64) && HAVE_DECL_HTOLE64 == 0
#   define htole64(v) ((uint64_t)v)
#  endif
#  ਜੇ defined(HAVE_DECL_HTOBE32) && HAVE_DECL_HTOBE32 == 0
#   define htobe32(v) (openssh_swap32(v))
#  endif
# endif
#ਜੇ_ਅੰਤ

/* Function replacement / compatibility hacks */

#ਜੇ !defined(HAVE_GETADDRINFO) && (defined(HAVE_OGETADDRINFO) || defined(HAVE_NGETADDRINFO))
# define HAVE_GETADDRINFO
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETOPT_OPTRESET
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
#ਜੇ_ਅੰਤ

#ਜੇ defined(BROKEN_GETADDRINFO) && defined(HAVE_GETADDRINFO)
# undef HAVE_GETADDRINFO
#ਜੇ_ਅੰਤ
#ਜੇ defined(BROKEN_GETADDRINFO) && defined(HAVE_FREEADDRINFO)
# undef HAVE_FREEADDRINFO
#ਜੇ_ਅੰਤ
#ਜੇ defined(BROKEN_GETADDRINFO) && defined(HAVE_GAI_STRERROR)
# undef HAVE_GAI_STRERROR
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_GETADDRINFO)
# ਜੇ defined(HAVE_DECL_AI_NUMERICSERV) && HAVE_DECL_AI_NUMERICSERV == 0
#   define AI_NUMERICSERV	0
# endif
#ਜੇ_ਅੰਤ

#ਜੇ defined(BROKEN_UPDWTMPX) && defined(HAVE_UPDWTMPX)
# undef HAVE_UPDWTMPX
#ਜੇ_ਅੰਤ

#ਜੇ defined(BROKEN_SHADOW_EXPIRE) && defined(HAS_SHADOW_EXPIRE)
# undef HAS_SHADOW_EXPIRE
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_OPENLOG_R) && defined(SYSLOG_ਅੰਕੜੇ_INIT) && \
    defined(SYSLOG_R_ਸੁਰੱਖਿਅਤ_ਵਿੱਚ_SIGHAND)
# define DO_LOG_ਸੁਰੱਖਿਅਤ_ਵਿੱਚ_SIGHAND
#ਜੇ_ਅੰਤ

#ਜੇ !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY)
# define memmove(s1, s2, n) bcopy((s2), (s1), (n))
#ਜੇ_ਅੰਤ /* !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY) */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ GETPGRP_VOID
# include <unistd.h>
# define getpgrp() getpgrp(0)
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_BSM_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LINUX_AUDIT
# define SSH_AUDIT_EVENTS
# define CUSTOM_SSH_AUDIT_EVENTS
#ਜੇ_ਅੰਤ

#ਜੇ !defined(HAVE___func__) && defined(HAVE___FUNCTION__)
#  define __func__ __FUNCTION__
#ਜਾਂਜੇ !defined(HAVE___func__)
#  define __func__ ""
#ਜੇ_ਅੰਤ

#ਜੇ defined(KRB5) && !defined(HEIMDAL)
#  define krb5_get_err_ਪਾਠ(context,ਕੋਡ) error_ਸੁਨੇਹਾ(ਕੋਡ)
#ਜੇ_ਅੰਤ

/* Maximum number of file descriptors available */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYSCONF
# define SSH_SYSFDMAX sysconf(_SC_OPEN_MAX)
#ਨਹੀਂਤਾਂ
# define SSH_SYSFDMAX 10000
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ FSID_HAS_VAL
/* encode f_fsid into a 64 bit value  */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FSID_ਮੰਜ਼ਿਲ_ULONG(f) \
	((((u_int64_t)(f).val[0] & 0xffffffffUL) << 32) | \
	    ((f).val[1] & 0xffffffffUL))
#ਜਾਂਜੇ defined(FSID_HAS___VAL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FSID_ਮੰਜ਼ਿਲ_ULONG(f) \
	((((u_int64_t)(f).__val[0] & 0xffffffffUL) << 32) | \
	    ((f).__val[1] & 0xffffffffUL))
#ਨਹੀਂਤਾਂ
# define FSID_ਮੰਜ਼ਿਲ_ULONG(f) ((f))
#ਜੇ_ਅੰਤ

#ਜੇ defined(__Lynx__)
 /*
  * LynxOS defines these in param.h which we do not want to include since
  * it will also pull in a bunch of kernel definitions.
  */
# define ALIGNBYTES (ਆਕਾਰ(ਪੂਰਨ) - 1)
# define ALIGN(p) (((ਬਿਨਾਨਿਸ਼ਾਨੀ)p + ALIGNBYTES) & ~ALIGNBYTES)
  /* Missing prototypes on LynxOS */
  ਪੂਰਨ snprintf (ਅੱਖਰ *, ਮਾਪ_t, ਅਚਲ ਅੱਖਰ *, ...);
  ਪੂਰਨ mkstemp (ਅੱਖਰ *);
  ਅੱਖਰ *crypt (ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
  ਪੂਰਨ seteuid (uid_t);
  ਪੂਰਨ setegid (gid_t);
  ਅੱਖਰ *mkdtemp (ਅੱਖਰ *);
  ਪੂਰਨ rresvport_af (ਪੂਰਨ *, sa_family_t);
  ਪੂਰਨ innetgr (ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
#ਜੇ_ਅੰਤ

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
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ UTMP_FILE
#  ifdef _PATH_UTMP
#    define UTMP_FILE _PATH_UTMP
#  ਨਹੀਂਤਾਂ
#    ifdef CONF_UTMP_FILE
#      define UTMP_FILE CONF_UTMP_FILE
#    endif
#  endif
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ WTMP_FILE
#  ifdef _PATH_WTMP
#    define WTMP_FILE _PATH_WTMP
#  ਨਹੀਂਤਾਂ
#    ifdef CONF_WTMP_FILE
#      define WTMP_FILE CONF_WTMP_FILE
#    endif
#  endif
#ਜੇ_ਅੰਤ
/* pick up the user's location for lastlog if given */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ LASTLOG_FILE
#  ifdef _PATH_LASTLOG
#    define LASTLOG_FILE _PATH_LASTLOG
#  ਨਹੀਂਤਾਂ
#    ifdef CONF_LASTLOG_FILE
#      define LASTLOG_FILE CONF_LASTLOG_FILE
#    endif
#  endif
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
# define USE_SHADOW
#ਜੇ_ਅੰਤ

/* The login() library function in libutil is first choice */
#ਜੇ defined(HAVE_LOGIN) && !defined(DISABLE_LOGIN)
#  define USE_LOGIN

#ਨਹੀਂਤਾਂ
/* Simply select your favourite login types. */
/* Can't do if-else because some systems use several... <sigh> */
#  ਜੇ !defined(DISABLE_UTMPX)
#    define USE_UTMPX
#  endif
#  ਜੇ defined(UTMP_FILE) && !defined(DISABLE_UTMP)
#    define USE_UTMP
#  endif
#  ਜੇ defined(WTMPX_FILE) && !defined(DISABLE_WTMPX)
#    define USE_WTMPX
#  endif
#  ਜੇ defined(WTMP_FILE) && !defined(DISABLE_WTMP)
#    define USE_WTMP
#  endif

#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ UT_LINESIZE
# define UT_LINESIZE 8
#ਜੇ_ਅੰਤ

/* I hope that the presence of LASTLOG_FILE is enough to detect this */
#ਜੇ defined(LASTLOG_FILE) && !defined(DISABLE_LASTLOG)
#  define USE_LASTLOG
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_OSF_SIA
# ifdef USE_SHADOW
#  undef USE_SHADOW
# endif
# define CUSTOM_SYS_AUTH_PASSWD 1
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_LIBIAF) && defined(HAVE_ਸੈੱਟ_ID) && !defined(HAVE_SECUREWARE)
# define CUSTOM_SYS_AUTH_PASSWD 1
#ਜੇ_ਅੰਤ
#ਜੇ defined(HAVE_LIBIAF) && defined(HAVE_ਸੈੱਟ_ID) && !defined(BROKEN_LIBIAF)
# define USE_LIBIAF
#ਜੇ_ਅੰਤ

/* HP-UX 11.11 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BTMP_FILE
# define ਰਸਤਾ_BTMP BTMP_FILE
#ਜੇ_ਅੰਤ

#ਜੇ defined(USE_BTMP) && defined(ਰਸਤਾ_BTMP)
# define CUSTOM_FAILED_LOGIN
#ਜੇ_ਅੰਤ

/** end of login recorder definitions */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BROKEN_GETGROUPS
# define getgroups(a,b) ((a)==0 && (b)==ਨਿਰਾ ? NGROUPS_MAX : getgroups((a),(b)))
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ IOV_MAX
# ਜੇ defined(_XOPEN_IOV_MAX)
#  define	IOV_MAX		_XOPEN_IOV_MAX
# elif defined(DEF_IOV_MAX)
#  define	IOV_MAX		DEF_IOV_MAX
# ਨਹੀਂਤਾਂ
#  define	IOV_MAX		16
# endif
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ EWOULDBLOCK
# define EWOULDBLOCK EAGAIN
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ INET6_ADDRSTRLEN	/* for non IPv6 machines */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ INET6_ADDRSTRLEN 46
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SSH_IOBUFSZ
# define SSH_IOBUFSZ 8192
#ਜੇ_ਅੰਤ

/*
 * We want functions in openbsd-compat, if enabled, to override system ones.
 * We no-op out the weak symbol definition rather than remove it to reduce
 * future sync problems.  Some compilers (eg Unixware) do not allow an
 * empty statement, so we use a bogus function declaration.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DEF_WEAK(x)	ਖਾਲੀ __ssh_compat_weak_##x(ਖਾਲੀ)

/*
 * Platforms that have arc4random_uniform() and not arc4random_stir()
 * shouldn't need the latter.
 */
#ਜੇ defined(HAVE_ARC4RANDOM) && defined(HAVE_ARC4_RANDOM_ਇਕਸਾਰ) && \
    !defined(HAVE_ARC4RANDOM_STIR)
# define arc4random_stir()
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_VA_COPY
# ifdef HAVE___VA_COPY
#  define va_copy(dest, src) __va_copy(dest, src)
# ਨਹੀਂਤਾਂ
#  define va_copy(dest, src) (dest) = (src)
# endif
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ __predict_true
# ਜੇ defined(__GNUC__) && \
     ((__GNUC__ > (2)) || (__GNUC__ == (2) && __GNUC_MINOR__ >= (96)))
#  define __predict_true(ਘਾਤਾਂਕ)     __builtin_expect(((ਘਾਤਾਂਕ) != 0), 1)
#  define __predict_false(ਘਾਤਾਂਕ)    __builtin_expect(((ਘਾਤਾਂਕ) != 0), 0)
# ਨਹੀਂਤਾਂ
#  define __predict_true(ਘਾਤਾਂਕ)     ((ਘਾਤਾਂਕ) != 0)
#  define __predict_false(ਘਾਤਾਂਕ)    ((ਘਾਤਾਂਕ) != 0)
# endif /* gcc version */
#ਜੇ_ਅੰਤ /* __predict_true */

/*
 * sntrup761 uses variable length arrays and c99-style declarations after code,
 * so only enable if the compiler supports them.
 */
#ਜੇ defined(VARIABLE_ਲੰਮਾਈ_ARRAYS) && defined(VARIABLE_DECLARATION_AFTER_ਕੋਡ)
# define USE_SNTRUP761X25519	1
/* The ML-KEM768 and ML-DSA implementations also uses C89 features */
# define USE_MLKEM768X25519	1
# define USE_MLDSA		1
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_DECL_INFINITY) && HAVE_DECL_INFINITY == 0
# ਜੇ defined(HAVE_DECL___BUILTIN_INFF) && HAVE_DECL___BUILTIN_INFF == 1
#  define INFINITY __builtin_inff()
# endif
#ਜੇ_ਅੰਤ

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
#ਜੇ defined(DISABLE_FD_PASSING) && !defined(HAVE_CYGWIN)
# define SKIP_PRIVDROP 1
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ /* _DEFINES_H */
