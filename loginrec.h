#ifndef _HAVE_LOGINREC_H_
#define _HAVE_LOGINREC_H_

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

#অন্তর্ভাব "includes.h"

কাঠামো ssh;

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/*
 * login_netinfo structure
 */

সংঘ login_netinfo {
	কাঠামো sockaddr sa;
	কাঠামো sockaddr_in sa_in;
	কাঠামো sockaddr_storage sa_storage;
};

/*
 *   * logininfo structure  *
 */
/* types - different to utmp.h 'type' macros */
/* (though set to the same value as linux, openbsd and others...) */
#define LTYPE_FAILED   6
#define LTYPE_LOGIN    7
#define LTYPE_LOGOUT   8

/* string lengths - set very long */
#define LINFO_PROGSIZE 64
#define LINFO_LINESIZE 64
#define LINFO_NAMESIZE 512
#define LINFO_HOSTSIZE 256

কাঠামো logininfo {
	অক্ষর       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	পূর্ণসংখ্যা        progname_null;
	short পূর্ণসংখ্যা  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	অক্ষর       সারি[LINFO_LINESIZE];         /* tty/pty name */
	অক্ষর       username[LINFO_NAMESIZE];     /* login username */
	অক্ষর       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	পূর্ণসংখ্যা        exit;                        /* process exit status */
	পূর্ণসংখ্যা        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	unsigned পূর্ণসংখ্যা tv_sec;
	unsigned পূর্ণসংখ্যা tv_usec;
	সংঘ login_netinfo hostaddr;       /* caller's host address(es) */
#ifdef USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#endif
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
কাঠামো logininfo *login_alloc_entry(pid_t pid, ধ্রুবক অক্ষর *username,
				    ধ্রুবক অক্ষর *hostname, ধ্রুবক অক্ষর *সারি);
/* free a structure */
শূন্য login_free_entry(কাঠামো logininfo *li);
/* fill out a pre-allocated structure with useful information */
পূর্ণসংখ্যা login_init_entry(কাঠামো logininfo *li, pid_t pid, ধ্রুবক অক্ষর *username,
    ধ্রুবক অক্ষর *hostname, ধ্রুবক অক্ষর *সারি);
/* place the current time in a logininfo struct */
শূন্য login_set_current_time(কাঠামো logininfo *li);

/* record the entry */
পূর্ণসংখ্যা login_login (কাঠামো logininfo *li);
পূর্ণসংখ্যা login_logout(কাঠামো logininfo *li);
#ifdef LOGIN_NEEDS_UTMPX
পূর্ণসংখ্যা login_utmp_only(কাঠামো logininfo *li);
#endif

/** End of public functions */

/* record the entry */
পূর্ণসংখ্যা login_write (কাঠামো logininfo *li);
পূর্ণসংখ্যা login_log_entry(কাঠামো logininfo *li);

/* set the network address based on network address type */
শূন্য login_set_addr(কাঠামো logininfo *li, ধ্রুবক কাঠামো sockaddr *sa,
		    ধ্রুবক unsigned পূর্ণসংখ্যা sa_আকার);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
কাঠামো logininfo *login_get_lastlog(কাঠামো logininfo *li, ধ্রুবক uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
unsigned পূর্ণসংখ্যা login_get_lastlog_time(ধ্রুবক uid_t uid);

/* produce various forms of the line filename */
অক্ষর *সারি_fullname(অক্ষর *dst, ধ্রুবক অক্ষর *src, u_int dstsize);
অক্ষর *সারি_stripname(অক্ষর *dst, ধ্রুবক অক্ষর *src, পূর্ণসংখ্যা dstsize);
অক্ষর *সারি_abbrevname(অক্ষর *dst, ধ্রুবক অক্ষর *src, পূর্ণসংখ্যা dstsize);

শূন্য record_failed_login(কাঠামো ssh *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *,
    ধ্রুবক অক্ষর *);

#endif /* _HAVE_LOGINREC_H_ */
