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

ସଂରଚନା ssh;
ସଂରଚନା sshbuf;

/* These should be in the system headers but are not. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା usrinfo(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#ଯଦି defined(HAVE_DECL_SETAUTHDB) && (HAVE_DECL_SETAUTHDB == 0)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା setauthdb(ଅଚଳ ଅକ୍ଷର *, ଅକ୍ଷର *);
#endif
/* these may or may not be in the headers depending on the version */
#ଯଦି defined(HAVE_DECL_AUTHENTICATE) && (HAVE_DECL_AUTHENTICATE == 0)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା authenticate(ଅକ୍ଷର *, ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ଅକ୍ଷର **);
#endif
#ଯଦି defined(HAVE_DECL_LOGINFAILED) && (HAVE_DECL_LOGINFAILED == 0)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା loginfailed(ଅକ୍ଷର *, ଅକ୍ଷର *, ଅକ୍ଷର *);
#endif
#ଯଦି defined(HAVE_DECL_LOGINRESTRICTIONS) && (HAVE_DECL_LOGINRESTRICTIONS == 0)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା loginrestrictions(ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର *, ଅକ୍ଷର **);
#endif
#ଯଦି defined(HAVE_DECL_LOGINSUCCESS) && (HAVE_DECL_LOGINSUCCESS == 0)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା loginsuccess(ଅକ୍ଷର *, ଅକ୍ଷର *, ଅକ୍ଷର *, ଅକ୍ଷର **);
#endif
#ଯଦି defined(HAVE_DECL_PASSWDEXPIRED) && (HAVE_DECL_PASSWDEXPIRED == 0)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା passwdexpired(ଅକ୍ଷର *, ଅକ୍ଷର **);
#endif

/* Some versions define r_type in the above headers, which causes a conflict */
#ifdef r_type
# undef r_type
#endif

/* AIX 4.2.x doesn't have nanosleep but does have nsleep which is equivalent */
#ଯଦି !defined(HAVE_NANOSLEEP) && defined(HAVE_NSLEEP)
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

ଶୂନ୍ୟ aix_usrinfo(ସଂରଚନା passwd *);

#ifdef WITH_AIXAUTHENTICATE
# define CUSTOM_SYS_AUTH_PASSWD 1
# define CUSTOM_SYS_AUTH_ALLOWED_USER 1
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sys_auth_allowed_user(ସଂରଚନା passwd *, ସଂରଚନା sshbuf *);
# define CUSTOM_SYS_AUTH_RECORD_LOGIN 1
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sys_auth_record_login(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *,
    ସଂରଚନା sshbuf *);
# define CUSTOM_SYS_AUTH_GET_LASTLOGIN_ସନ୍ଦେଶ
ଅକ୍ଷର *sys_auth_get_lastlogin_ସନ୍ଦେଶ(ଅଚଳ ଅକ୍ଷର *, uid_t);
# define CUSTOM_FAILED_LOGIN 1
# ଯଦି defined(S_AUTHDOMAIN)  && defined (S_AUTHNAME)
# define USE_AIX_KRB_NAME
ଅକ୍ଷର *aix_krb5_get_principal_name(ଅଚଳ ଅକ୍ଷର *);
# endif
#endif

ଶୂନ୍ୟ aix_setauthdb(ଅଚଳ ଅକ୍ଷର *);
ଶୂନ୍ୟ aix_restoreauthdb(ଶୂନ୍ୟ);
ଶୂନ୍ୟ aix_remove_embedded_newlines(ଅକ୍ଷର *);

#ଯଦି defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_GETADDRINFO)
# ifdef getnameinfo
#  undef getnameinfo
# endif
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshaix_getnameinfo(ଅଚଳ ସଂରଚନା sockaddr *, size_t, ଅକ୍ଷର *, size_t,
    ଅକ୍ଷର *, size_t, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
# define getnameinfo(a,b,c,d,e,f,g) (sshaix_getnameinfo(a,b,c,d,e,f,g))
#endif

/*
 * We use getgrset in preference to multiple getgrent calls for efficiency
 * plus it supports NIS and LDAP groups.
 */
#ଯଦି !defined(HAVE_GETGROUPLIST) && defined(HAVE_GETGRSET)
# define HAVE_GETGROUPLIST
# define USE_GETGRSET
ପୂର୍ଣ୍ଣସଂଖ୍ୟା getgrouplist(ଅଚଳ ଅକ୍ଷର *, gid_t, gid_t *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
#endif

#endif /* _AIX */
