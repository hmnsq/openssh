#جيڪڏهن_وصف_نه_ٿيل _HAVE_LOGINREC_H_
#وصف_ڪريو _HAVE_LOGINREC_H_

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
	بنية sockaddr_in sa_اندريون;
	بنية sockaddr_storage sa_storage;
};

/*
 *   * logininfo structure  *
 */
/* types - different to utmp.h 'type' macros */
/* (though set to the same value as linux, openbsd and others...) */
#وصف_ڪريو LTYPE_FAILED   6
#وصف_ڪريو LTYPE_LOGIN    7
#وصف_ڪريو LTYPE_LOGOUT   8

/* string lengths - set very long */
#وصف_ڪريو LINFO_PROGSIZE 64
#وصف_ڪريو LINFO_LINESIZE 64
#وصف_ڪريو LINFO_NAMESIZE 512
#وصف_ڪريو LINFO_HOSTSIZE 256

بنية logininfo {
	حرف       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	صحيح        progname_null;
	ننڍو صحيح  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	حرف       سٽ[LINFO_LINESIZE];         /* tty/pty name */
	حرف       username[LINFO_NAMESIZE];     /* login username */
	حرف       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	صحيح        ٻاهر_نڪرو;                        /* process exit status */
	صحيح        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	بنانشان صحيح tv_sec;
	بنانشان صحيح tv_usec;
	اتحاد login_netinfo hostaddr;       /* caller's host address(es) */
#جيڪڏهن_وصف_ٿيل USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#جيڪڏهن_پورو
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
بنية logininfo *login_alloc_داخلا(pid_t pid, ثابت حرف *username,
				    ثابت حرف *hostname, ثابت حرف *سٽ);
/* free a structure */
فراغ login_free_داخلا(بنية logininfo *li);
/* fill out a pre-allocated structure with useful information */
صحيح login_init_داخلا(بنية logininfo *li, pid_t pid, ثابت حرف *username,
    ثابت حرف *hostname, ثابت حرف *سٽ);
/* place the current time in a logininfo struct */
فراغ login_سيٽ_current_وقت(بنية logininfo *li);

/* record the entry */
صحيح login_login (بنية logininfo *li);
صحيح login_logout(بنية logininfo *li);
#جيڪڏهن_وصف_ٿيل LOGIN_NEEDS_UTMPX
صحيح login_utmp_only(بنية logininfo *li);
#جيڪڏهن_پورو

/** End of public functions */

/* record the entry */
صحيح login_write (بنية logininfo *li);
صحيح login_log_داخلا(بنية logininfo *li);

/* set the network address based on network address type */
فراغ login_سيٽ_addr(بنية logininfo *li, ثابت بنية sockaddr *sa,
		    ثابت بنانشان صحيح sa_سائيز);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
بنية logininfo *login_get_lastlog(بنية logininfo *li, ثابت uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
بنانشان صحيح login_get_lastlog_وقت(ثابت uid_t uid);

/* produce various forms of the line filename */
حرف *سٽ_fullname(حرف *dst, ثابت حرف *src, u_int dstsize);
حرف *سٽ_stripname(حرف *dst, ثابت حرف *src, صحيح dstsize);
حرف *سٽ_abbrevname(حرف *dst, ثابت حرف *src, صحيح dstsize);

فراغ رڪارڊ_failed_login(بنية ssh *, ثابت حرف *, ثابت حرف *,
    ثابت حرف *);

#جيڪڏهن_پورو /* _HAVE_LOGINREC_H_ */
