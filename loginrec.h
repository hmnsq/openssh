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

#अन्तर्भाव "includes.h"

संरचना ssh;

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/*
 * login_netinfo structure
 */

सङ्घ login_netinfo {
	संरचना sockaddr sa;
	संरचना sockaddr_in sa_in;
	संरचना sockaddr_storage sa_storage;
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

संरचना logininfo {
	वर्ण       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	पूर्णाङ्क        progname_null;
	लघु पूर्णाङ्क  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	वर्ण       पंक्ति[LINFO_LINESIZE];         /* tty/pty name */
	वर्ण       username[LINFO_NAMESIZE];     /* login username */
	वर्ण       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	पूर्णाङ्क        निकास;                        /* process exit status */
	पूर्णाङ्क        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	अचिन्हित पूर्णाङ्क tv_sec;
	अचिन्हित पूर्णाङ्क tv_usec;
	सङ्घ login_netinfo hostaddr;       /* caller's host address(es) */
#ifdef USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#endif
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
संरचना logininfo *login_alloc_entry(pid_t pid, ध्रुव वर्ण *username,
				    ध्रुव वर्ण *hostname, ध्रुव वर्ण *पंक्ति);
/* free a structure */
शून्य login_free_entry(संरचना logininfo *li);
/* fill out a pre-allocated structure with useful information */
पूर्णाङ्क login_init_entry(संरचना logininfo *li, pid_t pid, ध्रुव वर्ण *username,
    ध्रुव वर्ण *hostname, ध्रुव वर्ण *पंक्ति);
/* place the current time in a logininfo struct */
शून्य login_set_current_time(संरचना logininfo *li);

/* record the entry */
पूर्णाङ्क login_login (संरचना logininfo *li);
पूर्णाङ्क login_logout(संरचना logininfo *li);
#ifdef LOGIN_NEEDS_UTMPX
पूर्णाङ्क login_utmp_only(संरचना logininfo *li);
#endif

/** End of public functions */

/* record the entry */
पूर्णाङ्क login_write (संरचना logininfo *li);
पूर्णाङ्क login_log_entry(संरचना logininfo *li);

/* set the network address based on network address type */
शून्य login_set_addr(संरचना logininfo *li, ध्रुव संरचना sockaddr *sa,
		    ध्रुव अचिन्हित पूर्णाङ्क sa_size);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
संरचना logininfo *login_get_lastlog(संरचना logininfo *li, ध्रुव uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
अचिन्हित पूर्णाङ्क login_get_lastlog_time(ध्रुव uid_t uid);

/* produce various forms of the line filename */
वर्ण *पंक्ति_fullname(वर्ण *dst, ध्रुव वर्ण *src, u_int dstsize);
वर्ण *पंक्ति_stripname(वर्ण *dst, ध्रुव वर्ण *src, पूर्णाङ्क dstsize);
वर्ण *पंक्ति_abbrevname(वर्ण *dst, ध्रुव वर्ण *src, पूर्णाङ्क dstsize);

शून्य record_failed_login(संरचना ssh *, ध्रुव वर्ण *, ध्रुव वर्ण *,
    ध्रुव वर्ण *);

#endif /* _HAVE_LOGINREC_H_ */
