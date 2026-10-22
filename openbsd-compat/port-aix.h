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

#اگر_تعریف_شدہ _AIX

#اگر_تعریف_شدہ HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#اگر_ختم

ساخت ssh;
ساخت sshbuf;

/* These should be in the system headers but are not. */
صحیح usrinfo(صحیح, حرف *, صحیح);
#اگر defined(HAVE_DECL_SETAUTHDB) && (HAVE_DECL_SETAUTHDB == 0)
صحیح setauthdb(ثابت حرف *, حرف *);
#اگر_ختم
/* these may or may not be in the headers depending on the version */
#اگر defined(HAVE_DECL_AUTHENTICATE) && (HAVE_DECL_AUTHENTICATE == 0)
صحیح authenticate(حرف *, حرف *, صحیح *, حرف **);
#اگر_ختم
#اگر defined(HAVE_DECL_LOGINFAILED) && (HAVE_DECL_LOGINFAILED == 0)
صحیح loginfailed(حرف *, حرف *, حرف *);
#اگر_ختم
#اگر defined(HAVE_DECL_LOGINRESTRICTIONS) && (HAVE_DECL_LOGINRESTRICTIONS == 0)
صحیح loginrestrictions(حرف *, صحیح, حرف *, حرف **);
#اگر_ختم
#اگر defined(HAVE_DECL_LOGINSUCCESS) && (HAVE_DECL_LOGINSUCCESS == 0)
صحیح loginsuccess(حرف *, حرف *, حرف *, حرف **);
#اگر_ختم
#اگر defined(HAVE_DECL_PASSWDEXPIRED) && (HAVE_DECL_PASSWDEXPIRED == 0)
صحیح passwdexpired(حرف *, حرف **);
#اگر_ختم

/* Some versions define r_type in the above headers, which causes a conflict */
#اگر_تعریف_شدہ r_type
# undef r_type
#اگر_ختم

/* AIX 4.2.x doesn't have nanosleep but does have nsleep which is equivalent */
#اگر !defined(HAVE_NANOSLEEP) && defined(HAVE_NSLEEP)
# define nanosleep(a,b) nsleep(a,b)
#اگر_ختم

/* For struct timespec on AIX 4.2.x */
#اگر_تعریف_شدہ HAVE_SYS_TIMERS_H
# include <sys/timers.h>
#اگر_ختم

/* for setpcred and friends */
#اگر_تعریف_شدہ HAVE_USERSEC_H
# include <usersec.h>
#اگر_ختم

/*
 * According to the setauthdb man page, AIX password registries must be 15
 * chars or less plus terminating NUL.
 */
#اگر_تعریف_شدہ HAVE_SETAUTHDB
# define REGISTRY_سائز	16
#اگر_ختم

خالی aix_usrinfo(ساخت passwd *);

#اگر_تعریف_شدہ WITH_AIXAUTHENTICATE
# define CUSTOM_SYS_AUTH_PASSWD 1
# define CUSTOM_SYS_AUTH_ALLOWED_USER 1
صحیح sys_auth_allowed_user(ساخت passwd *, ساخت sshbuf *);
# define CUSTOM_SYS_AUTH_ریکارڈ_LOGIN 1
صحیح sys_auth_ریکارڈ_login(ثابت حرف *, ثابت حرف *, ثابت حرف *,
    ساخت sshbuf *);
# define CUSTOM_SYS_AUTH_GET_LASTLOGIN_پیغام
حرف *sys_auth_get_lastlogin_پیغام(ثابت حرف *, uid_t);
# define CUSTOM_FAILED_LOGIN 1
# اگر defined(S_AUTHDOMAIN)  && defined (S_AUTHNAME)
# define USE_AIX_KRB_NAME
حرف *aix_krb5_get_principal_name(ثابت حرف *);
# endif
#اگر_ختم

خالی aix_setauthdb(ثابت حرف *);
خالی aix_restoreauthdb(خالی);
خالی aix_remove_embedded_newlines(حرف *);

#اگر defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_GETADDRINFO)
# ifdef getnameinfo
#  undef getnameinfo
# endif
صحیح sshaix_getnameinfo(ثابت ساخت sockaddr *, سائز_t, حرف *, سائز_t,
    حرف *, سائز_t, صحیح);
# define getnameinfo(a,b,c,d,e,f,g) (sshaix_getnameinfo(a,b,c,d,e,f,g))
#اگر_ختم

/*
 * We use getgrset in preference to multiple getgrent calls for efficiency
 * plus it supports NIS and LDAP groups.
 */
#اگر !defined(HAVE_GETGROUPLIST) && defined(HAVE_GETGRSET)
# define HAVE_GETGROUPLIST
# define USE_GETGRSET
صحیح getgrouplist(ثابت حرف *, gid_t, gid_t *, صحیح *);
#اگر_ختم

#اگر_ختم /* _AIX */
