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

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ _AIX

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#ਜੇ_ਅੰਤ

ਬਣਤਰ ssh;
ਬਣਤਰ sshbuf;

/* These should be in the system headers but are not. */
ਪੂਰਨ usrinfo(ਪੂਰਨ, ਅੱਖਰ *, ਪੂਰਨ);
#ਜੇ defined(HAVE_DECL_SETAUTHDB) && (HAVE_DECL_SETAUTHDB == 0)
ਪੂਰਨ setauthdb(ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ *);
#ਜੇ_ਅੰਤ
/* these may or may not be in the headers depending on the version */
#ਜੇ defined(HAVE_DECL_AUTHENTICATE) && (HAVE_DECL_AUTHENTICATE == 0)
ਪੂਰਨ authenticate(ਅੱਖਰ *, ਅੱਖਰ *, ਪੂਰਨ *, ਅੱਖਰ **);
#ਜੇ_ਅੰਤ
#ਜੇ defined(HAVE_DECL_LOGINFAILED) && (HAVE_DECL_LOGINFAILED == 0)
ਪੂਰਨ loginfailed(ਅੱਖਰ *, ਅੱਖਰ *, ਅੱਖਰ *);
#ਜੇ_ਅੰਤ
#ਜੇ defined(HAVE_DECL_LOGINRESTRICTIONS) && (HAVE_DECL_LOGINRESTRICTIONS == 0)
ਪੂਰਨ loginrestrictions(ਅੱਖਰ *, ਪੂਰਨ, ਅੱਖਰ *, ਅੱਖਰ **);
#ਜੇ_ਅੰਤ
#ਜੇ defined(HAVE_DECL_LOGINSUCCESS) && (HAVE_DECL_LOGINSUCCESS == 0)
ਪੂਰਨ loginsuccess(ਅੱਖਰ *, ਅੱਖਰ *, ਅੱਖਰ *, ਅੱਖਰ **);
#ਜੇ_ਅੰਤ
#ਜੇ defined(HAVE_DECL_PASSWDEXPIRED) && (HAVE_DECL_PASSWDEXPIRED == 0)
ਪੂਰਨ passwdexpired(ਅੱਖਰ *, ਅੱਖਰ **);
#ਜੇ_ਅੰਤ

/* Some versions define r_type in the above headers, which causes a conflict */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ r_type
# undef r_type
#ਜੇ_ਅੰਤ

/* AIX 4.2.x doesn't have nanosleep but does have nsleep which is equivalent */
#ਜੇ !defined(HAVE_NANOSLEEP) && defined(HAVE_NSLEEP)
# define nanosleep(a,b) nsleep(a,b)
#ਜੇ_ਅੰਤ

/* For struct timespec on AIX 4.2.x */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_TIMERS_H
# include <sys/timers.h>
#ਜੇ_ਅੰਤ

/* for setpcred and friends */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_USERSEC_H
# include <usersec.h>
#ਜੇ_ਅੰਤ

/*
 * According to the setauthdb man page, AIX password registries must be 15
 * chars or less plus terminating NUL.
 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SETAUTHDB
# define REGISTRY_ਮਾਪ	16
#ਜੇ_ਅੰਤ

ਖਾਲੀ aix_usrinfo(ਬਣਤਰ passwd *);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_AIXAUTHENTICATE
# define CUSTOM_SYS_AUTH_PASSWD 1
# define CUSTOM_SYS_AUTH_ALLOWED_USER 1
ਪੂਰਨ sys_auth_allowed_user(ਬਣਤਰ passwd *, ਬਣਤਰ sshbuf *);
# define CUSTOM_SYS_AUTH_ਰਿਕਾਰਡ_LOGIN 1
ਪੂਰਨ sys_auth_ਰਿਕਾਰਡ_login(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
    ਬਣਤਰ sshbuf *);
# define CUSTOM_SYS_AUTH_GET_LASTLOGIN_ਸੁਨੇਹਾ
ਅੱਖਰ *sys_auth_get_lastlogin_ਸੁਨੇਹਾ(ਅਚਲ ਅੱਖਰ *, uid_t);
# define CUSTOM_FAILED_LOGIN 1
# ਜੇ defined(S_AUTHDOMAIN)  && defined (S_AUTHNAME)
# define USE_AIX_KRB_NAME
ਅੱਖਰ *aix_krb5_get_principal_name(ਅਚਲ ਅੱਖਰ *);
# endif
#ਜੇ_ਅੰਤ

ਖਾਲੀ aix_setauthdb(ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ aix_restoreauthdb(ਖਾਲੀ);
ਖਾਲੀ aix_remove_embedded_newlines(ਅੱਖਰ *);

#ਜੇ defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_GETADDRINFO)
# ifdef getnameinfo
#  undef getnameinfo
# endif
ਪੂਰਨ sshaix_getnameinfo(ਅਚਲ ਬਣਤਰ sockaddr *, ਮਾਪ_t, ਅੱਖਰ *, ਮਾਪ_t,
    ਅੱਖਰ *, ਮਾਪ_t, ਪੂਰਨ);
# define getnameinfo(a,b,c,d,e,f,g) (sshaix_getnameinfo(a,b,c,d,e,f,g))
#ਜੇ_ਅੰਤ

/*
 * We use getgrset in preference to multiple getgrent calls for efficiency
 * plus it supports NIS and LDAP groups.
 */
#ਜੇ !defined(HAVE_GETGROUPLIST) && defined(HAVE_GETGRSET)
# define HAVE_GETGROUPLIST
# define USE_GETGRSET
ਪੂਰਨ getgrouplist(ਅਚਲ ਅੱਖਰ *, gid_t, gid_t *, ਪੂਰਨ *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ /* _AIX */
