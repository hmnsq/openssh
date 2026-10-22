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

#അന്തര്ഭാവ "includes.h"

ഘടന ssh;

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/*
 * login_netinfo structure
 */

സംഘം login_netinfo {
	ഘടന sockaddr sa;
	ഘടന sockaddr_in sa_in;
	ഘടന sockaddr_storage sa_storage;
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

ഘടന logininfo {
	അക്ഷരം       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	പൂർണ്ണസംഖ്യ        progname_null;
	short പൂർണ്ണസംഖ്യ  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	അക്ഷരം       വരി[LINFO_LINESIZE];         /* tty/pty name */
	അക്ഷരം       username[LINFO_NAMESIZE];     /* login username */
	അക്ഷരം       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	പൂർണ്ണസംഖ്യ        exit;                        /* process exit status */
	പൂർണ്ണസംഖ്യ        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	unsigned പൂർണ്ണസംഖ്യ tv_sec;
	unsigned പൂർണ്ണസംഖ്യ tv_usec;
	സംഘം login_netinfo hostaddr;       /* caller's host address(es) */
#ifdef USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#endif
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
ഘടന logininfo *login_alloc_entry(pid_t pid, സ്ഥിരം അക്ഷരം *username,
				    സ്ഥിരം അക്ഷരം *hostname, സ്ഥിരം അക്ഷരം *വരി);
/* free a structure */
ശൂന്യം login_free_entry(ഘടന logininfo *li);
/* fill out a pre-allocated structure with useful information */
പൂർണ്ണസംഖ്യ login_init_entry(ഘടന logininfo *li, pid_t pid, സ്ഥിരം അക്ഷരം *username,
    സ്ഥിരം അക്ഷരം *hostname, സ്ഥിരം അക്ഷരം *വരി);
/* place the current time in a logininfo struct */
ശൂന്യം login_set_current_time(ഘടന logininfo *li);

/* record the entry */
പൂർണ്ണസംഖ്യ login_login (ഘടന logininfo *li);
പൂർണ്ണസംഖ്യ login_logout(ഘടന logininfo *li);
#ifdef LOGIN_NEEDS_UTMPX
പൂർണ്ണസംഖ്യ login_utmp_only(ഘടന logininfo *li);
#endif

/** End of public functions */

/* record the entry */
പൂർണ്ണസംഖ്യ login_write (ഘടന logininfo *li);
പൂർണ്ണസംഖ്യ login_log_entry(ഘടന logininfo *li);

/* set the network address based on network address type */
ശൂന്യം login_set_addr(ഘടന logininfo *li, സ്ഥിരം ഘടന sockaddr *sa,
		    സ്ഥിരം unsigned പൂർണ്ണസംഖ്യ sa_size);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
ഘടന logininfo *login_get_lastlog(ഘടന logininfo *li, സ്ഥിരം uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
unsigned പൂർണ്ണസംഖ്യ login_get_lastlog_time(സ്ഥിരം uid_t uid);

/* produce various forms of the line filename */
അക്ഷരം *വരി_fullname(അക്ഷരം *dst, സ്ഥിരം അക്ഷരം *src, u_int dstsize);
അക്ഷരം *വരി_stripname(അക്ഷരം *dst, സ്ഥിരം അക്ഷരം *src, പൂർണ്ണസംഖ്യ dstsize);
അക്ഷരം *വരി_abbrevname(അക്ഷരം *dst, സ്ഥിരം അക്ഷരം *src, പൂർണ്ണസംഖ്യ dstsize);

ശൂന്യം record_failed_login(ഘടന ssh *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം അക്ഷരം *);

#endif /* _HAVE_LOGINREC_H_ */
