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

#include "includes.h"

sa_nracanaa ssh;

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/*
 * login_netinfo structure
 */

sa_ngha login_netinfo {
	sa_nracanaa sockaddr sa;
	sa_nracanaa sockaddr_in sa_in;
	sa_nracanaa sockaddr_storage sa_storage;
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

sa_nracanaa logininfo {
	var_na       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	ཧྲིལ        progname_null;
	short ཧྲིལ  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	var_na       line[LINFO_LINESIZE];         /* tty/pty name */
	var_na       username[LINFO_NAMESIZE];     /* login username */
	var_na       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	ཧྲིལ        exit;                        /* process exit status */
	ཧྲིལ        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	unsigned ཧྲིལ tv_sec;
	unsigned ཧྲིལ tv_usec;
	sa_ngha login_netinfo hostaddr;       /* caller's host address(es) */
#ifdef USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#endif
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
sa_nracanaa logininfo *login_alloc_entry(pid_t pid, const var_na *username,
				    const var_na *hostname, const var_na *line);
/* free a structure */
void login_free_entry(sa_nracanaa logininfo *li);
/* fill out a pre-allocated structure with useful information */
ཧྲིལ login_init_entry(sa_nracanaa logininfo *li, pid_t pid, const var_na *username,
    const var_na *hostname, const var_na *line);
/* place the current time in a logininfo struct */
void login_set_current_time(sa_nracanaa logininfo *li);

/* record the entry */
ཧྲིལ login_login (sa_nracanaa logininfo *li);
ཧྲིལ login_logout(sa_nracanaa logininfo *li);
#ifdef LOGIN_NEEDS_UTMPX
ཧྲིལ login_utmp_only(sa_nracanaa logininfo *li);
#endif

/** End of public functions */

/* record the entry */
ཧྲིལ login_write (sa_nracanaa logininfo *li);
ཧྲིལ login_log_entry(sa_nracanaa logininfo *li);

/* set the network address based on network address type */
void login_set_addr(sa_nracanaa logininfo *li, const sa_nracanaa sockaddr *sa,
		    const unsigned ཧྲིལ sa_size);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
sa_nracanaa logininfo *login_get_lastlog(sa_nracanaa logininfo *li, const uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
unsigned ཧྲིལ login_get_lastlog_time(const uid_t uid);

/* produce various forms of the line filename */
var_na *line_fullname(var_na *dst, const var_na *src, u_int dstsize);
var_na *line_stripname(var_na *dst, const var_na *src, ཧྲིལ dstsize);
var_na *line_abbrevname(var_na *dst, const var_na *src, ཧྲིལ dstsize);

void record_failed_login(sa_nracanaa ssh *, const var_na *, const var_na *,
    const var_na *);

#endif /* _HAVE_LOGINREC_H_ */
