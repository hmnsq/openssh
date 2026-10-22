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

#அந்தர்பாவ "includes.h"

கட்டமைப்பு ssh;

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/*
 * login_netinfo structure
 */

ஒன்றிப்பு login_netinfo {
	கட்டமைப்பு sockaddr sa;
	கட்டமைப்பு sockaddr_in sa_in;
	கட்டமைப்பு sockaddr_storage sa_storage;
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

கட்டமைப்பு logininfo {
	எழுத்து       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	முழு        progname_null;
	short முழு  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	எழுத்து       வரி[LINFO_LINESIZE];         /* tty/pty name */
	எழுத்து       username[LINFO_NAMESIZE];     /* login username */
	எழுத்து       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	முழு        exit;                        /* process exit status */
	முழு        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	unsigned முழு tv_sec;
	unsigned முழு tv_usec;
	ஒன்றிப்பு login_netinfo hostaddr;       /* caller's host address(es) */
#ifdef USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#endif
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
கட்டமைப்பு logininfo *login_alloc_entry(pid_t pid, மாறிலி எழுத்து *username,
				    மாறிலி எழுத்து *hostname, மாறிலி எழுத்து *வரி);
/* free a structure */
வெறுமை login_free_entry(கட்டமைப்பு logininfo *li);
/* fill out a pre-allocated structure with useful information */
முழு login_init_entry(கட்டமைப்பு logininfo *li, pid_t pid, மாறிலி எழுத்து *username,
    மாறிலி எழுத்து *hostname, மாறிலி எழுத்து *வரி);
/* place the current time in a logininfo struct */
வெறுமை login_set_current_time(கட்டமைப்பு logininfo *li);

/* record the entry */
முழு login_login (கட்டமைப்பு logininfo *li);
முழு login_logout(கட்டமைப்பு logininfo *li);
#ifdef LOGIN_NEEDS_UTMPX
முழு login_utmp_only(கட்டமைப்பு logininfo *li);
#endif

/** End of public functions */

/* record the entry */
முழு login_write (கட்டமைப்பு logininfo *li);
முழு login_log_entry(கட்டமைப்பு logininfo *li);

/* set the network address based on network address type */
வெறுமை login_set_addr(கட்டமைப்பு logininfo *li, மாறிலி கட்டமைப்பு sockaddr *sa,
		    மாறிலி unsigned முழு sa_size);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
கட்டமைப்பு logininfo *login_get_lastlog(கட்டமைப்பு logininfo *li, மாறிலி uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
unsigned முழு login_get_lastlog_time(மாறிலி uid_t uid);

/* produce various forms of the line filename */
எழுத்து *வரி_fullname(எழுத்து *dst, மாறிலி எழுத்து *src, u_int dstsize);
எழுத்து *வரி_stripname(எழுத்து *dst, மாறிலி எழுத்து *src, முழு dstsize);
எழுத்து *வரி_abbrevname(எழுத்து *dst, மாறிலி எழுத்து *src, முழு dstsize);

வெறுமை record_failed_login(கட்டமைப்பு ssh *, மாறிலி எழுத்து *, மாறிலி எழுத்து *,
    மாறிலி எழுத்து *);

#endif /* _HAVE_LOGINREC_H_ */
