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

#నిర్వచితమైతే _AIX

#నిర్వచితమైతే HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#అయితే_ముగింపు

నిర్మాణం ssh;
నిర్మాణం sshbuf;

/* These should be in the system headers but are not. */
పూర్ణాంకం usrinfo(పూర్ణాంకం, అక్షరం *, పూర్ణాంకం);
#ఒకవేళ defined(HAVE_DECL_SETAUTHDB) && (HAVE_DECL_SETAUTHDB == 0)
పూర్ణాంకం setauthdb(స్థిరరాశి అక్షరం *, అక్షరం *);
#అయితే_ముగింపు
/* these may or may not be in the headers depending on the version */
#ఒకవేళ defined(HAVE_DECL_AUTHENTICATE) && (HAVE_DECL_AUTHENTICATE == 0)
పూర్ణాంకం authenticate(అక్షరం *, అక్షరం *, పూర్ణాంకం *, అక్షరం **);
#అయితే_ముగింపు
#ఒకవేళ defined(HAVE_DECL_LOGINFAILED) && (HAVE_DECL_LOGINFAILED == 0)
పూర్ణాంకం loginfailed(అక్షరం *, అక్షరం *, అక్షరం *);
#అయితే_ముగింపు
#ఒకవేళ defined(HAVE_DECL_LOGINRESTRICTIONS) && (HAVE_DECL_LOGINRESTRICTIONS == 0)
పూర్ణాంకం loginrestrictions(అక్షరం *, పూర్ణాంకం, అక్షరం *, అక్షరం **);
#అయితే_ముగింపు
#ఒకవేళ defined(HAVE_DECL_LOGINSUCCESS) && (HAVE_DECL_LOGINSUCCESS == 0)
పూర్ణాంకం loginsuccess(అక్షరం *, అక్షరం *, అక్షరం *, అక్షరం **);
#అయితే_ముగింపు
#ఒకవేళ defined(HAVE_DECL_PASSWDEXPIRED) && (HAVE_DECL_PASSWDEXPIRED == 0)
పూర్ణాంకం passwdexpired(అక్షరం *, అక్షరం **);
#అయితే_ముగింపు

/* Some versions define r_type in the above headers, which causes a conflict */
#నిర్వచితమైతే r_type
# undef r_type
#అయితే_ముగింపు

/* AIX 4.2.x doesn't have nanosleep but does have nsleep which is equivalent */
#ఒకవేళ !defined(HAVE_NANOSLEEP) && defined(HAVE_NSLEEP)
# define nanosleep(a,b) nsleep(a,b)
#అయితే_ముగింపు

/* For struct timespec on AIX 4.2.x */
#నిర్వచితమైతే HAVE_SYS_TIMERS_H
# include <sys/timers.h>
#అయితే_ముగింపు

/* for setpcred and friends */
#నిర్వచితమైతే HAVE_USERSEC_H
# include <usersec.h>
#అయితే_ముగింపు

/*
 * According to the setauthdb man page, AIX password registries must be 15
 * chars or less plus terminating NUL.
 */
#నిర్వచితమైతే HAVE_SETAUTHDB
# define REGISTRY_కొలత	16
#అయితే_ముగింపు

శూన్య aix_usrinfo(నిర్మాణం passwd *);

#నిర్వచితమైతే WITH_AIXAUTHENTICATE
# define CUSTOM_SYS_AUTH_PASSWD 1
# define CUSTOM_SYS_AUTH_ALLOWED_USER 1
పూర్ణాంకం sys_auth_allowed_user(నిర్మాణం passwd *, నిర్మాణం sshbuf *);
# define CUSTOM_SYS_AUTH_రికార్డు_LOGIN 1
పూర్ణాంకం sys_auth_రికార్డు_login(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
    నిర్మాణం sshbuf *);
# define CUSTOM_SYS_AUTH_GET_LASTLOGIN_సందేశం
అక్షరం *sys_auth_get_lastlogin_సందేశం(స్థిరరాశి అక్షరం *, uid_t);
# define CUSTOM_FAILED_LOGIN 1
# ఒకవేళ defined(S_AUTHDOMAIN)  && defined (S_AUTHNAME)
# define USE_AIX_KRB_NAME
అక్షరం *aix_krb5_get_principal_name(స్థిరరాశి అక్షరం *);
# endif
#అయితే_ముగింపు

శూన్య aix_setauthdb(స్థిరరాశి అక్షరం *);
శూన్య aix_restoreauthdb(శూన్య);
శూన్య aix_remove_embedded_newlines(అక్షరం *);

#ఒకవేళ defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_GETADDRINFO)
# ifdef getnameinfo
#  undef getnameinfo
# endif
పూర్ణాంకం sshaix_getnameinfo(స్థిరరాశి నిర్మాణం sockaddr *, కొలత_t, అక్షరం *, కొలత_t,
    అక్షరం *, కొలత_t, పూర్ణాంకం);
# define getnameinfo(a,b,c,d,e,f,g) (sshaix_getnameinfo(a,b,c,d,e,f,g))
#అయితే_ముగింపు

/*
 * We use getgrset in preference to multiple getgrent calls for efficiency
 * plus it supports NIS and LDAP groups.
 */
#ఒకవేళ !defined(HAVE_GETGROUPLIST) && defined(HAVE_GETGRSET)
# define HAVE_GETGROUPLIST
# define USE_GETGRSET
పూర్ణాంకం getgrouplist(స్థిరరాశి అక్షరం *, gid_t, gid_t *, పూర్ణాంకం *);
#అయితే_ముగింపు

#అయితే_ముగింపు /* _AIX */
