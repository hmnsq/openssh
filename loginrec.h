#यदि_अपरिभाषितम् _HAVE_LOGINREC_H_
#परिभाषय _HAVE_LOGINREC_H_

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
	संरचना sockaddr_in sa_अन्तर्;
	संरचना sockaddr_storage sa_storage;
};

/*
 *   * logininfo structure  *
 */
/* types - different to utmp.h 'type' macros */
/* (though set to the same value as linux, openbsd and others...) */
#परिभाषय LTYPE_FAILED   6
#परिभाषय LTYPE_LOGIN    7
#परिभाषय LTYPE_LOGOUT   8

/* string lengths - set very long */
#परिभाषय LINFO_PROGSIZE 64
#परिभाषय LINFO_LINESIZE 64
#परिभाषय LINFO_NAMESIZE 512
#परिभाषय LINFO_HOSTSIZE 256

संरचना logininfo {
	वर्ण       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	पूर्णाङ्क        progname_null;
	ह्रस्व पूर्णाङ्क  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	वर्ण       पङ्क्तिः[LINFO_LINESIZE];         /* tty/pty name */
	वर्ण       username[LINFO_NAMESIZE];     /* login username */
	वर्ण       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	पूर्णाङ्क        निर्गच्छ;                        /* process exit status */
	पूर्णाङ्क        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	अचिह्नित पूर्णाङ्क tv_sec;
	अचिह्नित पूर्णाङ्क tv_usec;
	सङ्घ login_netinfo hostaddr;       /* caller's host address(es) */
#यदि_परिभाषितम् USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#यदि_अन्तः
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
संरचना logininfo *login_alloc_प्रविष्टिः(pid_t pid, ध्रुव वर्ण *username,
				    ध्रुव वर्ण *hostname, ध्रुव वर्ण *पङ्क्तिः);
/* free a structure */
शून्य login_free_प्रविष्टिः(संरचना logininfo *li);
/* fill out a pre-allocated structure with useful information */
पूर्णाङ्क login_init_प्रविष्टिः(संरचना logininfo *li, pid_t pid, ध्रुव वर्ण *username,
    ध्रुव वर्ण *hostname, ध्रुव वर्ण *पङ्क्तिः);
/* place the current time in a logininfo struct */
शून्य login_समुच्चयः_current_time(संरचना logininfo *li);

/* record the entry */
पूर्णाङ्क login_login (संरचना logininfo *li);
पूर्णाङ्क login_logout(संरचना logininfo *li);
#यदि_परिभाषितम् LOGIN_NEEDS_UTMPX
पूर्णाङ्क login_utmp_only(संरचना logininfo *li);
#यदि_अन्तः

/** End of public functions */

/* record the entry */
पूर्णाङ्क login_write (संरचना logininfo *li);
पूर्णाङ्क login_log_प्रविष्टिः(संरचना logininfo *li);

/* set the network address based on network address type */
शून्य login_समुच्चयः_addr(संरचना logininfo *li, ध्रुव संरचना sockaddr *sa,
		    ध्रुव अचिह्नित पूर्णाङ्क sa_आकार);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
संरचना logininfo *login_get_lastlog(संरचना logininfo *li, ध्रुव uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
अचिह्नित पूर्णाङ्क login_get_lastlog_time(ध्रुव uid_t uid);

/* produce various forms of the line filename */
वर्ण *पङ्क्तिः_fullname(वर्ण *dst, ध्रुव वर्ण *src, u_int dstsize);
वर्ण *पङ्क्तिः_stripname(वर्ण *dst, ध्रुव वर्ण *src, पूर्णाङ्क dstsize);
वर्ण *पङ्क्तिः_abbrevname(वर्ण *dst, ध्रुव वर्ण *src, पूर्णाङ्क dstsize);

शून्य लेखः_failed_login(संरचना ssh *, ध्रुव वर्ण *, ध्रुव वर्ण *,
    ध्रुव वर्ण *);

#यदि_अन्तः /* _HAVE_LOGINREC_H_ */
