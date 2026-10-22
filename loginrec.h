#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _HAVE_LOGINREC_H_
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _HAVE_LOGINREC_H_

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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

ਬਣਤਰ ssh;

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/*
 * login_netinfo structure
 */

ਸੰਘ login_netinfo {
	ਬਣਤਰ sockaddr sa;
	ਬਣਤਰ sockaddr_in sa_ਵਿੱਚ;
	ਬਣਤਰ sockaddr_storage sa_storage;
};

/*
 *   * logininfo structure  *
 */
/* types - different to utmp.h 'type' macros */
/* (though set to the same value as linux, openbsd and others...) */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LTYPE_FAILED   6
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LTYPE_LOGIN    7
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LTYPE_LOGOUT   8

/* string lengths - set very long */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LINFO_PROGSIZE 64
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LINFO_LINESIZE 64
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LINFO_NAMESIZE 512
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LINFO_HOSTSIZE 256

ਬਣਤਰ logininfo {
	ਅੱਖਰ       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	ਪੂਰਨ        progname_null;
	ਛੋਟਾ ਪੂਰਨ  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	ਅੱਖਰ       ਸਤਰ[LINFO_LINESIZE];         /* tty/pty name */
	ਅੱਖਰ       username[LINFO_NAMESIZE];     /* login username */
	ਅੱਖਰ       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	ਪੂਰਨ        ਬਾਹਰ_ਨਿਕਲੋ;                        /* process exit status */
	ਪੂਰਨ        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ tv_sec;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ tv_usec;
	ਸੰਘ login_netinfo hostaddr;       /* caller's host address(es) */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#ਜੇ_ਅੰਤ
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
ਬਣਤਰ logininfo *login_alloc_ਇੰਦਰਾਜ(pid_t pid, ਅਚਲ ਅੱਖਰ *username,
				    ਅਚਲ ਅੱਖਰ *hostname, ਅਚਲ ਅੱਖਰ *ਸਤਰ);
/* free a structure */
ਖਾਲੀ login_free_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li);
/* fill out a pre-allocated structure with useful information */
ਪੂਰਨ login_init_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li, pid_t pid, ਅਚਲ ਅੱਖਰ *username,
    ਅਚਲ ਅੱਖਰ *hostname, ਅਚਲ ਅੱਖਰ *ਸਤਰ);
/* place the current time in a logininfo struct */
ਖਾਲੀ login_ਸੈੱਟ_current_ਸਮਾਂ(ਬਣਤਰ logininfo *li);

/* record the entry */
ਪੂਰਨ login_login (ਬਣਤਰ logininfo *li);
ਪੂਰਨ login_logout(ਬਣਤਰ logininfo *li);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LOGIN_NEEDS_UTMPX
ਪੂਰਨ login_utmp_only(ਬਣਤਰ logininfo *li);
#ਜੇ_ਅੰਤ

/** End of public functions */

/* record the entry */
ਪੂਰਨ login_write (ਬਣਤਰ logininfo *li);
ਪੂਰਨ login_log_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li);

/* set the network address based on network address type */
ਖਾਲੀ login_ਸੈੱਟ_addr(ਬਣਤਰ logininfo *li, ਅਚਲ ਬਣਤਰ sockaddr *sa,
		    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ sa_ਮਾਪ);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
ਬਣਤਰ logininfo *login_get_lastlog(ਬਣਤਰ logininfo *li, ਅਚਲ uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ login_get_lastlog_ਸਮਾਂ(ਅਚਲ uid_t uid);

/* produce various forms of the line filename */
ਅੱਖਰ *ਸਤਰ_fullname(ਅੱਖਰ *dst, ਅਚਲ ਅੱਖਰ *src, u_int dstsize);
ਅੱਖਰ *ਸਤਰ_stripname(ਅੱਖਰ *dst, ਅਚਲ ਅੱਖਰ *src, ਪੂਰਨ dstsize);
ਅੱਖਰ *ਸਤਰ_abbrevname(ਅੱਖਰ *dst, ਅਚਲ ਅੱਖਰ *src, ਪੂਰਨ dstsize);

ਖਾਲੀ ਰਿਕਾਰਡ_failed_login(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਅੱਖਰ *);

#ਜੇ_ਅੰਤ /* _HAVE_LOGINREC_H_ */
