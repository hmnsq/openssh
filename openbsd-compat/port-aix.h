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

কাঠামো ssh;
কাঠামো sshbuf;

/* These should be in the system headers but are not. */
পূর্ণসংখ্যা usrinfo(পূর্ণসংখ্যা, অক্ষর *, পূর্ণসংখ্যা);
#যদি defined(HAVE_DECL_SETAUTHDB) && (HAVE_DECL_SETAUTHDB == 0)
পূর্ণসংখ্যা setauthdb(ধ্রুবক অক্ষর *, অক্ষর *);
#endif
/* these may or may not be in the headers depending on the version */
#যদি defined(HAVE_DECL_AUTHENTICATE) && (HAVE_DECL_AUTHENTICATE == 0)
পূর্ণসংখ্যা authenticate(অক্ষর *, অক্ষর *, পূর্ণসংখ্যা *, অক্ষর **);
#endif
#যদি defined(HAVE_DECL_LOGINFAILED) && (HAVE_DECL_LOGINFAILED == 0)
পূর্ণসংখ্যা loginfailed(অক্ষর *, অক্ষর *, অক্ষর *);
#endif
#যদি defined(HAVE_DECL_LOGINRESTRICTIONS) && (HAVE_DECL_LOGINRESTRICTIONS == 0)
পূর্ণসংখ্যা loginrestrictions(অক্ষর *, পূর্ণসংখ্যা, অক্ষর *, অক্ষর **);
#endif
#যদি defined(HAVE_DECL_LOGINSUCCESS) && (HAVE_DECL_LOGINSUCCESS == 0)
পূর্ণসংখ্যা loginsuccess(অক্ষর *, অক্ষর *, অক্ষর *, অক্ষর **);
#endif
#যদি defined(HAVE_DECL_PASSWDEXPIRED) && (HAVE_DECL_PASSWDEXPIRED == 0)
পূর্ণসংখ্যা passwdexpired(অক্ষর *, অক্ষর **);
#endif

/* Some versions define r_type in the above headers, which causes a conflict */
#ifdef r_type
# undef r_type
#endif

/* AIX 4.2.x doesn't have nanosleep but does have nsleep which is equivalent */
#যদি !defined(HAVE_NANOSLEEP) && defined(HAVE_NSLEEP)
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
# define REGISTRY_আকার	16
#endif

শূন্য aix_usrinfo(কাঠামো passwd *);

#ifdef WITH_AIXAUTHENTICATE
# define CUSTOM_SYS_AUTH_PASSWD 1
# define CUSTOM_SYS_AUTH_ALLOWED_USER 1
পূর্ণসংখ্যা sys_auth_allowed_user(কাঠামো passwd *, কাঠামো sshbuf *);
# define CUSTOM_SYS_AUTH_RECORD_LOGIN 1
পূর্ণসংখ্যা sys_auth_record_login(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *,
    কাঠামো sshbuf *);
# define CUSTOM_SYS_AUTH_GET_LASTLOGIN_বার্তা
অক্ষর *sys_auth_get_lastlogin_বার্তা(ধ্রুবক অক্ষর *, uid_t);
# define CUSTOM_FAILED_LOGIN 1
# যদি defined(S_AUTHDOMAIN)  && defined (S_AUTHNAME)
# define USE_AIX_KRB_NAME
অক্ষর *aix_krb5_get_principal_name(ধ্রুবক অক্ষর *);
# endif
#endif

শূন্য aix_setauthdb(ধ্রুবক অক্ষর *);
শূন্য aix_restoreauthdb(শূন্য);
শূন্য aix_remove_embedded_newlines(অক্ষর *);

#যদি defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_GETADDRINFO)
# ifdef getnameinfo
#  undef getnameinfo
# endif
পূর্ণসংখ্যা sshaix_getnameinfo(ধ্রুবক কাঠামো sockaddr *, আকার_t, অক্ষর *, আকার_t,
    অক্ষর *, আকার_t, পূর্ণসংখ্যা);
# define getnameinfo(a,b,c,d,e,f,g) (sshaix_getnameinfo(a,b,c,d,e,f,g))
#endif

/*
 * We use getgrset in preference to multiple getgrent calls for efficiency
 * plus it supports NIS and LDAP groups.
 */
#যদি !defined(HAVE_GETGROUPLIST) && defined(HAVE_GETGRSET)
# define HAVE_GETGROUPLIST
# define USE_GETGRSET
পূর্ণসংখ্যা getgrouplist(ধ্রুবক অক্ষর *, gid_t, gid_t *, পূর্ণসংখ্যা *);
#endif

#endif /* _AIX */
