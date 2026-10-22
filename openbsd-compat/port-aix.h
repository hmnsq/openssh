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

#اگر_تعریف_شده _AIX

#اگر_تعریف_شده HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#پایان_اگر

بنية ssh;
بنية sshbuf;

/* These should be in the system headers but are not. */
صحيح usrinfo(صحيح, حرف *, صحيح);
#إذا defined(HAVE_DECL_SETAUTHDB) && (HAVE_DECL_SETAUTHDB == 0)
صحيح setauthdb(ثابت حرف *, حرف *);
#پایان_اگر
/* these may or may not be in the headers depending on the version */
#إذا defined(HAVE_DECL_AUTHENTICATE) && (HAVE_DECL_AUTHENTICATE == 0)
صحيح authenticate(حرف *, حرف *, صحيح *, حرف **);
#پایان_اگر
#إذا defined(HAVE_DECL_LOGINFAILED) && (HAVE_DECL_LOGINFAILED == 0)
صحيح loginfailed(حرف *, حرف *, حرف *);
#پایان_اگر
#إذا defined(HAVE_DECL_LOGINRESTRICTIONS) && (HAVE_DECL_LOGINRESTRICTIONS == 0)
صحيح loginrestrictions(حرف *, صحيح, حرف *, حرف **);
#پایان_اگر
#إذا defined(HAVE_DECL_LOGINSUCCESS) && (HAVE_DECL_LOGINSUCCESS == 0)
صحيح loginsuccess(حرف *, حرف *, حرف *, حرف **);
#پایان_اگر
#إذا defined(HAVE_DECL_PASSWDEXPIRED) && (HAVE_DECL_PASSWDEXPIRED == 0)
صحيح passwdexpired(حرف *, حرف **);
#پایان_اگر

/* Some versions define r_type in the above headers, which causes a conflict */
#اگر_تعریف_شده r_type
# undef r_type
#پایان_اگر

/* AIX 4.2.x doesn't have nanosleep but does have nsleep which is equivalent */
#إذا !defined(HAVE_NANOSLEEP) && defined(HAVE_NSLEEP)
# define nanosleep(a,b) nsleep(a,b)
#پایان_اگر

/* For struct timespec on AIX 4.2.x */
#اگر_تعریف_شده HAVE_SYS_TIMERS_H
# include <sys/timers.h>
#پایان_اگر

/* for setpcred and friends */
#اگر_تعریف_شده HAVE_USERSEC_H
# include <usersec.h>
#پایان_اگر

/*
 * According to the setauthdb man page, AIX password registries must be 15
 * chars or less plus terminating NUL.
 */
#اگر_تعریف_شده HAVE_SETAUTHDB
# define REGISTRY_اندازه	16
#پایان_اگر

فراغ aix_usrinfo(بنية passwd *);

#اگر_تعریف_شده WITH_AIXAUTHENTICATE
# define CUSTOM_SYS_AUTH_PASSWD 1
# define CUSTOM_SYS_AUTH_ALLOWED_USER 1
صحيح sys_auth_allowed_user(بنية passwd *, بنية sshbuf *);
# define CUSTOM_SYS_AUTH_رکورد_LOGIN 1
صحيح sys_auth_رکورد_login(ثابت حرف *, ثابت حرف *, ثابت حرف *,
    بنية sshbuf *);
# define CUSTOM_SYS_AUTH_GET_LASTLOGIN_پیام
حرف *sys_auth_get_lastlogin_پیام(ثابت حرف *, uid_t);
# define CUSTOM_FAILED_LOGIN 1
# إذا defined(S_AUTHDOMAIN)  && defined (S_AUTHNAME)
# define USE_AIX_KRB_NAME
حرف *aix_krb5_get_principal_name(ثابت حرف *);
# endif
#پایان_اگر

فراغ aix_setauthdb(ثابت حرف *);
فراغ aix_restoreauthdb(فراغ);
فراغ aix_remove_embedded_newlines(حرف *);

#إذا defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_GETADDRINFO)
# ifdef getnameinfo
#  undef getnameinfo
# endif
صحيح sshaix_getnameinfo(ثابت بنية sockaddr *, اندازه_t, حرف *, اندازه_t,
    حرف *, اندازه_t, صحيح);
# define getnameinfo(a,b,c,d,e,f,g) (sshaix_getnameinfo(a,b,c,d,e,f,g))
#پایان_اگر

/*
 * We use getgrset in preference to multiple getgrent calls for efficiency
 * plus it supports NIS and LDAP groups.
 */
#إذا !defined(HAVE_GETGROUPLIST) && defined(HAVE_GETGRSET)
# define HAVE_GETGROUPLIST
# define USE_GETGRSET
صحيح getgrouplist(ثابت حرف *, gid_t, gid_t *, صحيح *);
#پایان_اگر

#پایان_اگر /* _AIX */
