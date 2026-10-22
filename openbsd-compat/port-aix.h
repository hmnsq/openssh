/*
 *
 * Copyright (c) 2001 Gert Doering.  All rights reserved.
 * Copyright (c) 2004,2005,2006 Darren Tucker.  All rights reserved.
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

#ifdef _AIX

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

struct ssh;
struct sshbuf;

/* These should be in the system headers but are not. */
ціле usrinfo(ціле, char *, ціле);
#якщо defined(HAVE_DECL_SETAUTHDB) && (HAVE_DECL_SETAUTHDB == 0)
ціле setauthdb(const char *, char *);
#endif
/* these may or may not be in the headers depending on the version */
#якщо defined(HAVE_DECL_AUTHENTICATE) && (HAVE_DECL_AUTHENTICATE == 0)
ціле authenticate(char *, char *, ціле *, char **);
#endif
#якщо defined(HAVE_DECL_LOGINFAILED) && (HAVE_DECL_LOGINFAILED == 0)
ціле loginfailed(char *, char *, char *);
#endif
#якщо defined(HAVE_DECL_LOGINRESTRICTIONS) && (HAVE_DECL_LOGINRESTRICTIONS == 0)
ціле loginrestrictions(char *, ціле, char *, char **);
#endif
#якщо defined(HAVE_DECL_LOGINSUCCESS) && (HAVE_DECL_LOGINSUCCESS == 0)
ціле loginsuccess(char *, char *, char *, char **);
#endif
#якщо defined(HAVE_DECL_PASSWDEXPIRED) && (HAVE_DECL_PASSWDEXPIRED == 0)
ціле passwdexpired(char *, char **);
#endif

/* Some versions define r_type in the above headers, which causes a conflict */
#ifdef r_type
# undef r_type
#endif

/* AIX 4.2.x doesn't have nanosleep but does have nsleep which is equivalent */
#якщо !defined(HAVE_NANOSLEEP) && defined(HAVE_NSLEEP)
# define nanosleep(a,b) nsleep(a,b)
#endif

/* For struct timespec on AIX 4.2.x */
#ifdef HAVE_SYS_TIMERS_H
# include <sys/timers.h>
#endif

/* for setpcred and friends */
#ifdef HAVE_USERSEC_H
# include <usersec.h>
#endif

/*
 * According to the setauthdb man page, AIX password registries must be 15
 * chars or less plus terminating NUL.
 */
#ifdef HAVE_SETAUTHDB
# define REGISTRY_SIZE	16
#endif

void aix_usrinfo(struct passwd *);

#ifdef WITH_AIXAUTHENTICATE
# define CUSTOM_SYS_AUTH_PASSWD 1
# define CUSTOM_SYS_AUTH_ALLOWED_USER 1
ціле sys_auth_allowed_user(struct passwd *, struct sshbuf *);
# define CUSTOM_SYS_AUTH_RECORD_LOGIN 1
ціле sys_auth_record_login(const char *, const char *, const char *,
    struct sshbuf *);
# define CUSTOM_SYS_AUTH_GET_LASTLOGIN_MSG
char *sys_auth_get_lastlogin_msg(const char *, uid_t);
# define CUSTOM_FAILED_LOGIN 1
# якщо defined(S_AUTHDOMAIN)  && defined (S_AUTHNAME)
# define USE_AIX_KRB_NAME
char *aix_krb5_get_principal_name(const char *);
# endif
#endif

void aix_setauthdb(const char *);
void aix_restoreauthdb(void);
void aix_remove_embedded_newlines(char *);

#якщо defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_GETADDRINFO)
# ifdef getnameinfo
#  undef getnameinfo
# endif
ціле sshaix_getnameinfo(const struct sockaddr *, size_t, char *, size_t,
    char *, size_t, ціле);
# define getnameinfo(a,b,c,d,e,f,g) (sshaix_getnameinfo(a,b,c,d,e,f,g))
#endif

/*
 * We use getgrset in preference to multiple getgrent calls for efficiency
 * plus it supports NIS and LDAP groups.
 */
#якщо !defined(HAVE_GETGROUPLIST) && defined(HAVE_GETGRSET)
# define HAVE_GETGROUPLIST
# define USE_GETGRSET
ціле getgrouplist(const char *, gid_t, gid_t *, ціле *);
#endif

#endif /* _AIX */
