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

#ضمن "includes.h"

بنية ssh;

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/*
 * login_netinfo structure
 */

اتحاد login_netinfo {
	بنية sockaddr sa;
	بنية sockaddr_in sa_in;
	بنية sockaddr_storage sa_storage;
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

بنية logininfo {
	حرف       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	صحيح        progname_null;
	short صحيح  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	حرف       لي[LINFO_LINESIZE];         /* tty/pty name */
	حرف       username[LINFO_NAMESIZE];     /* login username */
	حرف       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	صحيح        exit;                        /* process exit status */
	صحيح        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	unsigned صحيح tv_sec;
	unsigned صحيح tv_usec;
	اتحاد login_netinfo hostaddr;       /* caller's host address(es) */
#ifdef USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#endif
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
بنية logininfo *login_alloc_entry(pid_t pid, ثابت حرف *username,
				    ثابت حرف *hostname, ثابت حرف *لي);
/* free a structure */
فراغ login_free_entry(بنية logininfo *li);
/* fill out a pre-allocated structure with useful information */
صحيح login_init_entry(بنية logininfo *li, pid_t pid, ثابت حرف *username,
    ثابت حرف *hostname, ثابت حرف *لي);
/* place the current time in a logininfo struct */
فراغ login_set_current_time(بنية logininfo *li);

/* record the entry */
صحيح login_login (بنية logininfo *li);
صحيح login_logout(بنية logininfo *li);
#ifdef LOGIN_NEEDS_UTMPX
صحيح login_utmp_only(بنية logininfo *li);
#endif

/** End of public functions */

/* record the entry */
صحيح login_write (بنية logininfo *li);
صحيح login_log_entry(بنية logininfo *li);

/* set the network address based on network address type */
فراغ login_set_addr(بنية logininfo *li, ثابت بنية sockaddr *sa,
		    ثابت unsigned صحيح sa_size);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
بنية logininfo *login_get_lastlog(بنية logininfo *li, ثابت uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
unsigned صحيح login_get_lastlog_time(ثابت uid_t uid);

/* produce various forms of the line filename */
حرف *لي_fullname(حرف *dst, ثابت حرف *src, u_int dstsize);
حرف *لي_stripname(حرف *dst, ثابت حرف *src, صحيح dstsize);
حرف *لي_abbrevname(حرف *dst, ثابت حرف *src, صحيح dstsize);

فراغ record_failed_login(بنية ssh *, ثابت حرف *, ثابت حرف *,
    ثابت حرف *);

#endif /* _HAVE_LOGINREC_H_ */
