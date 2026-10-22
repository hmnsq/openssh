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

#ଅନ୍ତର୍ଭାଵ "includes.h"

ସଂରଚନା ssh;

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/*
 * login_netinfo structure
 */

ସଂଘ login_netinfo {
	ସଂରଚନା sockaddr sa;
	ସଂରଚନା sockaddr_in sa_in;
	ସଂରଚନା sockaddr_storage sa_storage;
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

ସଂରଚନା logininfo {
	ଅକ୍ଷର       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା        progname_null;
	short ପୂର୍ଣ୍ଣସଂଖ୍ୟା  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	ଅକ୍ଷର       ଧାଡ଼ି[LINFO_LINESIZE];         /* tty/pty name */
	ଅକ୍ଷର       username[LINFO_NAMESIZE];     /* login username */
	ଅକ୍ଷର       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା        exit;                        /* process exit status */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା tv_sec;
	unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା tv_usec;
	ସଂଘ login_netinfo hostaddr;       /* caller's host address(es) */
#ifdef USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#endif
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
ସଂରଚନା logininfo *login_alloc_entry(pid_t pid, ଅଚଳ ଅକ୍ଷର *username,
				    ଅଚଳ ଅକ୍ଷର *hostname, ଅଚଳ ଅକ୍ଷର *ଧାଡ଼ି);
/* free a structure */
ଶୂନ୍ୟ login_free_entry(ସଂରଚନା logininfo *li);
/* fill out a pre-allocated structure with useful information */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା login_init_entry(ସଂରଚନା logininfo *li, pid_t pid, ଅଚଳ ଅକ୍ଷର *username,
    ଅଚଳ ଅକ୍ଷର *hostname, ଅଚଳ ଅକ୍ଷର *ଧାଡ଼ି);
/* place the current time in a logininfo struct */
ଶୂନ୍ୟ login_set_current_time(ସଂରଚନା logininfo *li);

/* record the entry */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା login_login (ସଂରଚନା logininfo *li);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା login_logout(ସଂରଚନା logininfo *li);
#ifdef LOGIN_NEEDS_UTMPX
ପୂର୍ଣ୍ଣସଂଖ୍ୟା login_utmp_only(ସଂରଚନା logininfo *li);
#endif

/** End of public functions */

/* record the entry */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା login_write (ସଂରଚନା logininfo *li);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା login_log_entry(ସଂରଚନା logininfo *li);

/* set the network address based on network address type */
ଶୂନ୍ୟ login_set_addr(ସଂରଚନା logininfo *li, ଅଚଳ ସଂରଚନା sockaddr *sa,
		    ଅଚଳ unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା sa_size);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
ସଂରଚନା logininfo *login_get_lastlog(ସଂରଚନା logininfo *li, ଅଚଳ uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା login_get_lastlog_time(ଅଚଳ uid_t uid);

/* produce various forms of the line filename */
ଅକ୍ଷର *ଧାଡ଼ି_fullname(ଅକ୍ଷର *dst, ଅଚଳ ଅକ୍ଷର *src, u_int dstsize);
ଅକ୍ଷର *ଧାଡ଼ି_stripname(ଅକ୍ଷର *dst, ଅଚଳ ଅକ୍ଷର *src, ପୂର୍ଣ୍ଣସଂଖ୍ୟା dstsize);
ଅକ୍ଷର *ଧାଡ଼ି_abbrevname(ଅକ୍ଷର *dst, ଅଚଳ ଅକ୍ଷର *src, ପୂର୍ଣ୍ଣସଂଖ୍ୟା dstsize);

ଶୂନ୍ୟ record_failed_login(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ଅକ୍ଷର *);

#endif /* _HAVE_LOGINREC_H_ */
