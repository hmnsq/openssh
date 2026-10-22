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

#অন্তর্ভাৱ "includes.h"

সংরচনা ssh;

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/*
 * login_netinfo structure
 */

সঙ্ঘ login_netinfo {
	সংরচনা sockaddr sa;
	সংরচনা sockaddr_in sa_in;
	সংরচনা sockaddr_storage sa_storage;
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

সংরচনা logininfo {
	ৱর্ণ       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	পূর্ণাঙ্ক        progname_null;
	short পূর্ণাঙ্ক  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	ৱর্ণ       সাৰি[LINFO_LINESIZE];         /* tty/pty name */
	ৱর্ণ       username[LINFO_NAMESIZE];     /* login username */
	ৱর্ণ       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	পূর্ণাঙ্ক        exit;                        /* process exit status */
	পূর্ণাঙ্ক        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	unsigned পূর্ণাঙ্ক tv_sec;
	unsigned পূর্ণাঙ্ক tv_usec;
	সঙ্ঘ login_netinfo hostaddr;       /* caller's host address(es) */
#ifdef USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#endif
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
সংরচনা logininfo *login_alloc_entry(pid_t pid, ধ্রুৱ ৱর্ণ *username,
				    ধ্রুৱ ৱর্ণ *hostname, ধ্রুৱ ৱর্ণ *সাৰি);
/* free a structure */
শূন্য login_free_entry(সংরচনা logininfo *li);
/* fill out a pre-allocated structure with useful information */
পূর্ণাঙ্ক login_init_entry(সংরচনা logininfo *li, pid_t pid, ধ্রুৱ ৱর্ণ *username,
    ধ্রুৱ ৱর্ণ *hostname, ধ্রুৱ ৱর্ণ *সাৰি);
/* place the current time in a logininfo struct */
শূন্য login_set_current_time(সংরচনা logininfo *li);

/* record the entry */
পূর্ণাঙ্ক login_login (সংরচনা logininfo *li);
পূর্ণাঙ্ক login_logout(সংরচনা logininfo *li);
#ifdef LOGIN_NEEDS_UTMPX
পূর্ণাঙ্ক login_utmp_only(সংরচনা logininfo *li);
#endif

/** End of public functions */

/* record the entry */
পূর্ণাঙ্ক login_write (সংরচনা logininfo *li);
পূর্ণাঙ্ক login_log_entry(সংরচনা logininfo *li);

/* set the network address based on network address type */
শূন্য login_set_addr(সংরচনা logininfo *li, ধ্রুৱ সংরচনা sockaddr *sa,
		    ধ্রুৱ unsigned পূর্ণাঙ্ক sa_size);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
সংরচনা logininfo *login_get_lastlog(সংরচনা logininfo *li, ধ্রুৱ uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
unsigned পূর্ণাঙ্ক login_get_lastlog_time(ধ্রুৱ uid_t uid);

/* produce various forms of the line filename */
ৱর্ণ *সাৰি_fullname(ৱর্ণ *dst, ধ্রুৱ ৱর্ণ *src, u_int dstsize);
ৱর্ণ *সাৰি_stripname(ৱর্ণ *dst, ধ্রুৱ ৱর্ণ *src, পূর্ণাঙ্ক dstsize);
ৱর্ণ *সাৰি_abbrevname(ৱর্ণ *dst, ধ্রুৱ ৱর্ণ *src, পূর্ণাঙ্ক dstsize);

শূন্য record_failed_login(সংরচনা ssh *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *,
    ধ্রুৱ ৱর্ণ *);

#endif /* _HAVE_LOGINREC_H_ */
