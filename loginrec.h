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

#شامل "includes.h"

ساختار ssh;

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/*
 * login_netinfo structure
 */

اجتماع login_netinfo {
	ساختار sockaddr sa;
	ساختار sockaddr_in sa_in;
	ساختار sockaddr_storage sa_storage;
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

ساختار logininfo {
	نویسه       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	صحیح        progname_null;
	short صحیح  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	نویسه       سطر[LINFO_LINESIZE];         /* tty/pty name */
	نویسه       username[LINFO_NAMESIZE];     /* login username */
	نویسه       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	صحیح        exit;                        /* process exit status */
	صحیح        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	unsigned صحیح tv_sec;
	unsigned صحیح tv_usec;
	اجتماع login_netinfo hostaddr;       /* caller's host address(es) */
#ifdef USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#endif
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
ساختار logininfo *login_alloc_entry(pid_t pid, ثابت نویسه *username,
				    ثابت نویسه *hostname, ثابت نویسه *سطر);
/* free a structure */
تهی login_free_entry(ساختار logininfo *li);
/* fill out a pre-allocated structure with useful information */
صحیح login_init_entry(ساختار logininfo *li, pid_t pid, ثابت نویسه *username,
    ثابت نویسه *hostname, ثابت نویسه *سطر);
/* place the current time in a logininfo struct */
تهی login_set_current_time(ساختار logininfo *li);

/* record the entry */
صحیح login_login (ساختار logininfo *li);
صحیح login_logout(ساختار logininfo *li);
#ifdef LOGIN_NEEDS_UTMPX
صحیح login_utmp_only(ساختار logininfo *li);
#endif

/** End of public functions */

/* record the entry */
صحیح login_write (ساختار logininfo *li);
صحیح login_log_entry(ساختار logininfo *li);

/* set the network address based on network address type */
تهی login_set_addr(ساختار logininfo *li, ثابت ساختار sockaddr *sa,
		    ثابت unsigned صحیح sa_size);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
ساختار logininfo *login_get_lastlog(ساختار logininfo *li, ثابت uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
unsigned صحیح login_get_lastlog_time(ثابت uid_t uid);

/* produce various forms of the line filename */
نویسه *سطر_fullname(نویسه *dst, ثابت نویسه *src, u_int dstsize);
نویسه *سطر_stripname(نویسه *dst, ثابت نویسه *src, صحیح dstsize);
نویسه *سطر_abbrevname(نویسه *dst, ثابت نویسه *src, صحیح dstsize);

تهی record_failed_login(ساختار ssh *, ثابت نویسه *, ثابت نویسه *,
    ثابت نویسه *);

#endif /* _HAVE_LOGINREC_H_ */
