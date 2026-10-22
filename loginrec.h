#अगर_अघोषित _HAVE_LOGINREC_H_
#घोषणा _HAVE_LOGINREC_H_

/*
 * Copyright (c) 2000 Andre Lucas.  All rights reserved.
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

/**
 ** loginrec.h:  platform-independent login recording and lastlog retrieval
 **/

#समावेश "includes.h"

काष्ठा ssh;

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/*
 * login_netinfo structure
 */

जोड़ login_netinfo {
	काष्ठा sockaddr sa;
	काष्ठा sockaddr_in sa_in;
	काष्ठा sockaddr_storage sa_storage;
};

/*
 *   * logininfo structure  *
 */
/* types - different to utmp.h 'type' macros */
/* (though set to the same value as linux, openbsd and others...) */
#घोषणा LTYPE_FAILED   6
#घोषणा LTYPE_LOGIN    7
#घोषणा LTYPE_LOGOUT   8

/* string lengths - set very long */
#घोषणा LINFO_PROGSIZE 64
#घोषणा LINFO_LINESIZE 64
#घोषणा LINFO_NAMESIZE 512
#घोषणा LINFO_HOSTSIZE 256

काष्ठा logininfo {
	अक्षर       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	पूर्णांक        progname_null;
	लघु पूर्णांक  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	अक्षर       पंक्ति[LINFO_LINESIZE];         /* tty/pty name */
	अक्षर       username[LINFO_NAMESIZE];     /* login username */
	अक्षर       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	पूर्णांक        निकास;                        /* process exit status */
	पूर्णांक        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	अचिन्हित पूर्णांक tv_sec;
	अचिन्हित पूर्णांक tv_usec;
	जोड़ login_netinfo hostaddr;       /* caller's host address(es) */
#अगर_घोषित USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#पूर्ण_अगर
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
काष्ठा logininfo *login_alloc_entry(pid_t pid, स्थिर अक्षर *username,
				    स्थिर अक्षर *hostname, स्थिर अक्षर *पंक्ति);
/* free a structure */
व्योम login_free_entry(काष्ठा logininfo *li);
/* fill out a pre-allocated structure with useful information */
पूर्णांक login_init_entry(काष्ठा logininfo *li, pid_t pid, स्थिर अक्षर *username,
    स्थिर अक्षर *hostname, स्थिर अक्षर *पंक्ति);
/* place the current time in a logininfo struct */
व्योम login_set_current_time(काष्ठा logininfo *li);

/* record the entry */
पूर्णांक login_login (काष्ठा logininfo *li);
पूर्णांक login_logout(काष्ठा logininfo *li);
#अगर_घोषित LOGIN_NEEDS_UTMPX
पूर्णांक login_utmp_only(काष्ठा logininfo *li);
#पूर्ण_अगर

/** End of public functions */

/* record the entry */
पूर्णांक login_write (काष्ठा logininfo *li);
पूर्णांक login_log_entry(काष्ठा logininfo *li);

/* set the network address based on network address type */
व्योम login_set_addr(काष्ठा logininfo *li, स्थिर काष्ठा sockaddr *sa,
		    स्थिर अचिन्हित पूर्णांक sa_आकार);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
काष्ठा logininfo *login_get_lastlog(काष्ठा logininfo *li, स्थिर uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
अचिन्हित पूर्णांक login_get_lastlog_time(स्थिर uid_t uid);

/* produce various forms of the line filename */
अक्षर *पंक्ति_fullname(अक्षर *dst, स्थिर अक्षर *src, u_int dstsize);
अक्षर *पंक्ति_stripname(अक्षर *dst, स्थिर अक्षर *src, पूर्णांक dstsize);
अक्षर *पंक्ति_abbrevname(अक्षर *dst, स्थिर अक्षर *src, पूर्णांक dstsize);

व्योम record_failed_login(काष्ठा ssh *, स्थिर अक्षर *, स्थिर अक्षर *,
    स्थिर अक्षर *);

#पूर्ण_अगर /* _HAVE_LOGINREC_H_ */
