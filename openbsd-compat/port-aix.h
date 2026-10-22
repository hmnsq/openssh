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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ _AIX

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#ಆದರೆ_ಅಂತ್ಯ

ರಚನೆ ssh;
ರಚನೆ sshbuf;

/* These should be in the system headers but are not. */
ಪೂರ್ಣಾಂಕ usrinfo(ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ defined(HAVE_DECL_SETAUTHDB) && (HAVE_DECL_SETAUTHDB == 0)
ಪೂರ್ಣಾಂಕ setauthdb(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *);
#ಆದರೆ_ಅಂತ್ಯ
/* these may or may not be in the headers depending on the version */
#ಆದರೆ defined(HAVE_DECL_AUTHENTICATE) && (HAVE_DECL_AUTHENTICATE == 0)
ಪೂರ್ಣಾಂಕ authenticate(ಅಕ್ಷರ *, ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ *, ಅಕ್ಷರ **);
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(HAVE_DECL_LOGINFAILED) && (HAVE_DECL_LOGINFAILED == 0)
ಪೂರ್ಣಾಂಕ loginfailed(ಅಕ್ಷರ *, ಅಕ್ಷರ *, ಅಕ್ಷರ *);
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(HAVE_DECL_LOGINRESTRICTIONS) && (HAVE_DECL_LOGINRESTRICTIONS == 0)
ಪೂರ್ಣಾಂಕ loginrestrictions(ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ *, ಅಕ್ಷರ **);
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(HAVE_DECL_LOGINSUCCESS) && (HAVE_DECL_LOGINSUCCESS == 0)
ಪೂರ್ಣಾಂಕ loginsuccess(ಅಕ್ಷರ *, ಅಕ್ಷರ *, ಅಕ್ಷರ *, ಅಕ್ಷರ **);
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(HAVE_DECL_PASSWDEXPIRED) && (HAVE_DECL_PASSWDEXPIRED == 0)
ಪೂರ್ಣಾಂಕ passwdexpired(ಅಕ್ಷರ *, ಅಕ್ಷರ **);
#ಆದರೆ_ಅಂತ್ಯ

/* Some versions define r_type in the above headers, which causes a conflict */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ r_type
# undef r_type
#ಆದರೆ_ಅಂತ್ಯ

/* AIX 4.2.x doesn't have nanosleep but does have nsleep which is equivalent */
#ಆದರೆ !defined(HAVE_NANOSLEEP) && defined(HAVE_NSLEEP)
# define nanosleep(a,b) nsleep(a,b)
#ಆದರೆ_ಅಂತ್ಯ

/* For struct timespec on AIX 4.2.x */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_TIMERS_H
# include <sys/timers.h>
#ಆದರೆ_ಅಂತ್ಯ

/* for setpcred and friends */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_USERSEC_H
# include <usersec.h>
#ಆದರೆ_ಅಂತ್ಯ

/*
 * According to the setauthdb man page, AIX password registries must be 15
 * chars or less plus terminating NUL.
 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SETAUTHDB
# define REGISTRY_ಗಾತ್ರ	16
#ಆದರೆ_ಅಂತ್ಯ

ಶೂನ್ಯ aix_usrinfo(ರಚನೆ passwd *);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_AIXAUTHENTICATE
# define CUSTOM_SYS_AUTH_PASSWD 1
# define CUSTOM_SYS_AUTH_ALLOWED_USER 1
ಪೂರ್ಣಾಂಕ sys_auth_allowed_user(ರಚನೆ passwd *, ರಚನೆ sshbuf *);
# define CUSTOM_SYS_AUTH_ದಾಖಲೆ_LOGIN 1
ಪೂರ್ಣಾಂಕ sys_auth_ದಾಖಲೆ_login(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ರಚನೆ sshbuf *);
# define CUSTOM_SYS_AUTH_GET_LASTLOGIN_ಸಂದೇಶ
ಅಕ್ಷರ *sys_auth_get_lastlogin_ಸಂದೇಶ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, uid_t);
# define CUSTOM_FAILED_LOGIN 1
# ಆದರೆ defined(S_AUTHDOMAIN)  && defined (S_AUTHNAME)
# define USE_AIX_KRB_NAME
ಅಕ್ಷರ *aix_krb5_get_principal_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
# endif
#ಆದರೆ_ಅಂತ್ಯ

ಶೂನ್ಯ aix_setauthdb(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ aix_restoreauthdb(ಶೂನ್ಯ);
ಶೂನ್ಯ aix_remove_embedded_newlines(ಅಕ್ಷರ *);

#ಆದರೆ defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_GETADDRINFO)
# ifdef getnameinfo
#  undef getnameinfo
# endif
ಪೂರ್ಣಾಂಕ sshaix_getnameinfo(ಸ್ಥಿರಾಂಕ ರಚನೆ sockaddr *, ಗಾತ್ರ_t, ಅಕ್ಷರ *, ಗಾತ್ರ_t,
    ಅಕ್ಷರ *, ಗಾತ್ರ_t, ಪೂರ್ಣಾಂಕ);
# define getnameinfo(a,b,c,d,e,f,g) (sshaix_getnameinfo(a,b,c,d,e,f,g))
#ಆದರೆ_ಅಂತ್ಯ

/*
 * We use getgrset in preference to multiple getgrent calls for efficiency
 * plus it supports NIS and LDAP groups.
 */
#ಆದರೆ !defined(HAVE_GETGROUPLIST) && defined(HAVE_GETGRSET)
# define HAVE_GETGROUPLIST
# define USE_GETGRSET
ಪೂರ್ಣಾಂಕ getgrouplist(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, gid_t, gid_t *, ಪೂರ್ಣಾಂಕ *);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ /* _AIX */
