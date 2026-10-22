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

#ಅನ್ತರ್ಭಾವ "includes.h"

ಸಂರಚನಾ ssh;

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/*
 * login_netinfo structure
 */

ಸಙ್ಘ login_netinfo {
	ಸಂರಚನಾ sockaddr sa;
	ಸಂರಚನಾ sockaddr_in sa_in;
	ಸಂರಚನಾ sockaddr_storage sa_storage;
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

ಸಂರಚನಾ logininfo {
	ವರ್ಣ       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	ಪೂರ್ಣಾಙ್ಕ        progname_null;
	short ಪೂರ್ಣಾಙ್ಕ  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	ವರ್ಣ       ಸಾಲು[LINFO_LINESIZE];         /* tty/pty name */
	ವರ್ಣ       username[LINFO_NAMESIZE];     /* login username */
	ವರ್ಣ       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	ಪೂರ್ಣಾಙ್ಕ        exit;                        /* process exit status */
	ಪೂರ್ಣಾಙ್ಕ        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	unsigned ಪೂರ್ಣಾಙ್ಕ tv_sec;
	unsigned ಪೂರ್ಣಾಙ್ಕ tv_usec;
	ಸಙ್ಘ login_netinfo hostaddr;       /* caller's host address(es) */
#ifdef USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#endif
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
ಸಂರಚನಾ logininfo *login_alloc_entry(pid_t pid, ಧ್ರುವ ವರ್ಣ *username,
				    ಧ್ರುವ ವರ್ಣ *hostname, ಧ್ರುವ ವರ್ಣ *ಸಾಲು);
/* free a structure */
ಶೂನ್ಯ login_free_entry(ಸಂರಚನಾ logininfo *li);
/* fill out a pre-allocated structure with useful information */
ಪೂರ್ಣಾಙ್ಕ login_init_entry(ಸಂರಚನಾ logininfo *li, pid_t pid, ಧ್ರುವ ವರ್ಣ *username,
    ಧ್ರುವ ವರ್ಣ *hostname, ಧ್ರುವ ವರ್ಣ *ಸಾಲು);
/* place the current time in a logininfo struct */
ಶೂನ್ಯ login_set_current_time(ಸಂರಚನಾ logininfo *li);

/* record the entry */
ಪೂರ್ಣಾಙ್ಕ login_login (ಸಂರಚನಾ logininfo *li);
ಪೂರ್ಣಾಙ್ಕ login_logout(ಸಂರಚನಾ logininfo *li);
#ifdef LOGIN_NEEDS_UTMPX
ಪೂರ್ಣಾಙ್ಕ login_utmp_only(ಸಂರಚನಾ logininfo *li);
#endif

/** End of public functions */

/* record the entry */
ಪೂರ್ಣಾಙ್ಕ login_write (ಸಂರಚನಾ logininfo *li);
ಪೂರ್ಣಾಙ್ಕ login_log_entry(ಸಂರಚನಾ logininfo *li);

/* set the network address based on network address type */
ಶೂನ್ಯ login_set_addr(ಸಂರಚನಾ logininfo *li, ಧ್ರುವ ಸಂರಚನಾ sockaddr *sa,
		    ಧ್ರುವ unsigned ಪೂರ್ಣಾಙ್ಕ sa_size);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
ಸಂರಚನಾ logininfo *login_get_lastlog(ಸಂರಚನಾ logininfo *li, ಧ್ರುವ uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
unsigned ಪೂರ್ಣಾಙ್ಕ login_get_lastlog_time(ಧ್ರುವ uid_t uid);

/* produce various forms of the line filename */
ವರ್ಣ *ಸಾಲು_fullname(ವರ್ಣ *dst, ಧ್ರುವ ವರ್ಣ *src, u_int dstsize);
ವರ್ಣ *ಸಾಲು_stripname(ವರ್ಣ *dst, ಧ್ರುವ ವರ್ಣ *src, ಪೂರ್ಣಾಙ್ಕ dstsize);
ವರ್ಣ *ಸಾಲು_abbrevname(ವರ್ಣ *dst, ಧ್ರುವ ವರ್ಣ *src, ಪೂರ್ಣಾಙ್ಕ dstsize);

ಶೂನ್ಯ record_failed_login(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ವರ್ಣ *);

#endif /* _HAVE_LOGINREC_H_ */
