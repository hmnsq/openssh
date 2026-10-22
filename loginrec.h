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

#અન્તર્ભાવ "includes.h"

સંરચના ssh;

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/*
 * login_netinfo structure
 */

સંઘ login_netinfo {
	સંરચના sockaddr sa;
	સંરચના sockaddr_in sa_in;
	સંરચના sockaddr_storage sa_storage;
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

સંરચના logininfo {
	અક્ષર       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	પૂર્ણાંક        progname_null;
	short પૂર્ણાંક  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	અક્ષર       લીટી[LINFO_LINESIZE];         /* tty/pty name */
	અક્ષર       username[LINFO_NAMESIZE];     /* login username */
	અક્ષર       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	પૂર્ણાંક        exit;                        /* process exit status */
	પૂર્ણાંક        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	unsigned પૂર્ણાંક tv_sec;
	unsigned પૂર્ણાંક tv_usec;
	સંઘ login_netinfo hostaddr;       /* caller's host address(es) */
#ifdef USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#endif
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
સંરચના logininfo *login_alloc_entry(pid_t pid, અચલ અક્ષર *username,
				    અચલ અક્ષર *hostname, અચલ અક્ષર *લીટી);
/* free a structure */
શૂન્ય login_free_entry(સંરચના logininfo *li);
/* fill out a pre-allocated structure with useful information */
પૂર્ણાંક login_init_entry(સંરચના logininfo *li, pid_t pid, અચલ અક્ષર *username,
    અચલ અક્ષર *hostname, અચલ અક્ષર *લીટી);
/* place the current time in a logininfo struct */
શૂન્ય login_set_current_time(સંરચના logininfo *li);

/* record the entry */
પૂર્ણાંક login_login (સંરચના logininfo *li);
પૂર્ણાંક login_logout(સંરચના logininfo *li);
#ifdef LOGIN_NEEDS_UTMPX
પૂર્ણાંક login_utmp_only(સંરચના logininfo *li);
#endif

/** End of public functions */

/* record the entry */
પૂર્ણાંક login_write (સંરચના logininfo *li);
પૂર્ણાંક login_log_entry(સંરચના logininfo *li);

/* set the network address based on network address type */
શૂન્ય login_set_addr(સંરચના logininfo *li, અચલ સંરચના sockaddr *sa,
		    અચલ unsigned પૂર્ણાંક sa_size);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
સંરચના logininfo *login_get_lastlog(સંરચના logininfo *li, અચલ uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
unsigned પૂર્ણાંક login_get_lastlog_time(અચલ uid_t uid);

/* produce various forms of the line filename */
અક્ષર *લીટી_fullname(અક્ષર *dst, અચલ અક્ષર *src, u_int dstsize);
અક્ષર *લીટી_stripname(અક્ષર *dst, અચલ અક્ષર *src, પૂર્ણાંક dstsize);
અક્ષર *લીટી_abbrevname(અક્ષર *dst, અચલ અક્ષર *src, પૂર્ણાંક dstsize);

શૂન્ય record_failed_login(સંરચના ssh *, અચલ અક્ષર *, અચલ અક્ષર *,
    અચલ અક્ષર *);

#endif /* _HAVE_LOGINREC_H_ */
