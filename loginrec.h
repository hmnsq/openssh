#నిర్వచితం_కాకపోతే _HAVE_LOGINREC_H_
#నిర్వచించు _HAVE_LOGINREC_H_

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

#అన్తర్భావ "includes.h"

నిర్మాణం ssh;

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/*
 * login_netinfo structure
 */

సంఘం login_netinfo {
	నిర్మాణం sockaddr sa;
	నిర్మాణం sockaddr_in sa_లోపల;
	నిర్మాణం sockaddr_storage sa_storage;
};

/*
 *   * logininfo structure  *
 */
/* types - different to utmp.h 'type' macros */
/* (though set to the same value as linux, openbsd and others...) */
#నిర్వచించు LTYPE_FAILED   6
#నిర్వచించు LTYPE_LOGIN    7
#నిర్వచించు LTYPE_LOGOUT   8

/* string lengths - set very long */
#నిర్వచించు LINFO_PROGSIZE 64
#నిర్వచించు LINFO_LINESIZE 64
#నిర్వచించు LINFO_NAMESIZE 512
#నిర్వచించు LINFO_HOSTSIZE 256

నిర్మాణం logininfo {
	అక్షరం       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	పూర్ణాంకం        progname_null;
	పొట్టి పూర్ణాంకం  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	అక్షరం       పంక్తి[LINFO_LINESIZE];         /* tty/pty name */
	అక్షరం       username[LINFO_NAMESIZE];     /* login username */
	అక్షరం       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	పూర్ణాంకం        నిష్క్రమించు;                        /* process exit status */
	పూర్ణాంకం        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	గుర్తులేని పూర్ణాంకం tv_sec;
	గుర్తులేని పూర్ణాంకం tv_usec;
	సంఘం login_netinfo hostaddr;       /* caller's host address(es) */
#నిర్వచితమైతే USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#అయితే_ముగింపు
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
నిర్మాణం logininfo *login_alloc_నమోదు(pid_t pid, స్థిరరాశి అక్షరం *username,
				    స్థిరరాశి అక్షరం *hostname, స్థిరరాశి అక్షరం *పంక్తి);
/* free a structure */
శూన్య login_free_నమోదు(నిర్మాణం logininfo *li);
/* fill out a pre-allocated structure with useful information */
పూర్ణాంకం login_init_నమోదు(నిర్మాణం logininfo *li, pid_t pid, స్థిరరాశి అక్షరం *username,
    స్థిరరాశి అక్షరం *hostname, స్థిరరాశి అక్షరం *పంక్తి);
/* place the current time in a logininfo struct */
శూన్య login_సమితి_current_సమయం(నిర్మాణం logininfo *li);

/* record the entry */
పూర్ణాంకం login_login (నిర్మాణం logininfo *li);
పూర్ణాంకం login_logout(నిర్మాణం logininfo *li);
#నిర్వచితమైతే LOGIN_NEEDS_UTMPX
పూర్ణాంకం login_utmp_only(నిర్మాణం logininfo *li);
#అయితే_ముగింపు

/** End of public functions */

/* record the entry */
పూర్ణాంకం login_write (నిర్మాణం logininfo *li);
పూర్ణాంకం login_log_నమోదు(నిర్మాణం logininfo *li);

/* set the network address based on network address type */
శూన్య login_సమితి_addr(నిర్మాణం logininfo *li, స్థిరరాశి నిర్మాణం sockaddr *sa,
		    స్థిరరాశి గుర్తులేని పూర్ణాంకం sa_కొలత);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
నిర్మాణం logininfo *login_get_lastlog(నిర్మాణం logininfo *li, స్థిరరాశి uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
గుర్తులేని పూర్ణాంకం login_get_lastlog_సమయం(స్థిరరాశి uid_t uid);

/* produce various forms of the line filename */
అక్షరం *పంక్తి_fullname(అక్షరం *dst, స్థిరరాశి అక్షరం *src, u_int dstsize);
అక్షరం *పంక్తి_stripname(అక్షరం *dst, స్థిరరాశి అక్షరం *src, పూర్ణాంకం dstsize);
అక్షరం *పంక్తి_abbrevname(అక్షరం *dst, స్థిరరాశి అక్షరం *src, పూర్ణాంకం dstsize);

శూన్య రికార్డు_failed_login(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి అక్షరం *);

#అయితే_ముగింపు /* _HAVE_LOGINREC_H_ */
