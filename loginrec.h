#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _HAVE_LOGINREC_H_
#ವ್ಯಾಖ್ಯಾನಿಸು _HAVE_LOGINREC_H_

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

#ಅನ್ತರ್ಭಾವ "includes.h"

ರಚನೆ ssh;

/**
 ** you should use the login_* calls to work around platform dependencies
 **/

/*
 * login_netinfo structure
 */

ಒಕ್ಕೂಟ login_netinfo {
	ರಚನೆ sockaddr sa;
	ರಚನೆ sockaddr_in sa_ಒಳ;
	ರಚನೆ sockaddr_storage sa_storage;
};

/*
 *   * logininfo structure  *
 */
/* types - different to utmp.h 'type' macros */
/* (though set to the same value as linux, openbsd and others...) */
#ವ್ಯಾಖ್ಯಾನಿಸು LTYPE_FAILED   6
#ವ್ಯಾಖ್ಯಾನಿಸು LTYPE_LOGIN    7
#ವ್ಯಾಖ್ಯಾನಿಸು LTYPE_LOGOUT   8

/* string lengths - set very long */
#ವ್ಯಾಖ್ಯಾನಿಸು LINFO_PROGSIZE 64
#ವ್ಯಾಖ್ಯಾನಿಸು LINFO_LINESIZE 64
#ವ್ಯಾಖ್ಯಾನಿಸು LINFO_NAMESIZE 512
#ವ್ಯಾಖ್ಯಾನಿಸು LINFO_HOSTSIZE 256

ರಚನೆ logininfo {
	ಅಕ್ಷರ       progname[LINFO_PROGSIZE];     /* name of program (for PAM) */
	ಪೂರ್ಣಾಂಕ        progname_null;
	ಗಿಡ್ಡ ಪೂರ್ಣಾಂಕ  type;                         /* type of login (LTYPE_*) */
	pid_t      pid;                          /* PID of login process */
	uid_t      uid;                          /* UID of this user */
	ಅಕ್ಷರ       ಸಾಲು[LINFO_LINESIZE];         /* tty/pty name */
	ಅಕ್ಷರ       username[LINFO_NAMESIZE];     /* login username */
	ಅಕ್ಷರ       hostname[LINFO_HOSTSIZE];     /* remote hostname */
	/* 'exit_status' structure components */
	ಪೂರ್ಣಾಂಕ        ನಿರ್ಗಮಿಸು;                        /* process exit status */
	ಪೂರ್ಣಾಂಕ        termination;                 /* process termination status */
	/* struct timeval (sys/time.h) isn't always available, if it isn't we'll
	 * use time_t's value as tv_sec and set tv_usec to 0
	 */
	ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ tv_sec;
	ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ tv_usec;
	ಒಕ್ಕೂಟ login_netinfo hostaddr;       /* caller's host address(es) */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_WTMPDB
	int64_t wtmpdb_id;                  /* ID for wtmpdb_logout */
#ಆದರೆ_ಅಂತ್ಯ
}; /* struct logininfo */

/*
 * login recording functions
 */

/** 'public' functions */

/* construct a new login entry */
ರಚನೆ logininfo *login_alloc_ನಮೂದು(pid_t pid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *username,
				    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಾಲು);
/* free a structure */
ಶೂನ್ಯ login_free_ನಮೂದು(ರಚನೆ logininfo *li);
/* fill out a pre-allocated structure with useful information */
ಪೂರ್ಣಾಂಕ login_init_ನಮೂದು(ರಚನೆ logininfo *li, pid_t pid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *username,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಾಲು);
/* place the current time in a logininfo struct */
ಶೂನ್ಯ login_ಗಣ_current_ಸಮಯ(ರಚನೆ logininfo *li);

/* record the entry */
ಪೂರ್ಣಾಂಕ login_login (ರಚನೆ logininfo *li);
ಪೂರ್ಣಾಂಕ login_logout(ರಚನೆ logininfo *li);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LOGIN_NEEDS_UTMPX
ಪೂರ್ಣಾಂಕ login_utmp_only(ರಚನೆ logininfo *li);
#ಆದರೆ_ಅಂತ್ಯ

/** End of public functions */

/* record the entry */
ಪೂರ್ಣಾಂಕ login_write (ರಚನೆ logininfo *li);
ಪೂರ್ಣಾಂಕ login_log_ನಮೂದು(ರಚನೆ logininfo *li);

/* set the network address based on network address type */
ಶೂನ್ಯ login_ಗಣ_addr(ರಚನೆ logininfo *li, ಸ್ಥಿರಾಂಕ ರಚನೆ sockaddr *sa,
		    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ sa_ಗಾತ್ರ);

/*
 * lastlog retrieval functions
 */
/* lastlog *entry* functions fill out a logininfo */
ರಚನೆ logininfo *login_get_lastlog(ರಚನೆ logininfo *li, ಸ್ಥಿರಾಂಕ uid_t uid);
/* lastlog *time* functions return time_t equivalent (uint) */
ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ login_get_lastlog_ಸಮಯ(ಸ್ಥಿರಾಂಕ uid_t uid);

/* produce various forms of the line filename */
ಅಕ್ಷರ *ಸಾಲು_fullname(ಅಕ್ಷರ *dst, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, u_int dstsize);
ಅಕ್ಷರ *ಸಾಲು_stripname(ಅಕ್ಷರ *dst, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಪೂರ್ಣಾಂಕ dstsize);
ಅಕ್ಷರ *ಸಾಲು_abbrevname(ಅಕ್ಷರ *dst, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಪೂರ್ಣಾಂಕ dstsize);

ಶೂನ್ಯ ದಾಖಲೆ_failed_login(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

#ಆದರೆ_ಅಂತ್ಯ /* _HAVE_LOGINREC_H_ */
