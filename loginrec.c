/*
 * Copyright (c) 2000 Andre Lucas.  All rights reserved.
 * Portions copyright (c) 1998 Todd C. Miller
 * Portions copyright (c) 1996 Jason Downs
 * Portions copyright (c) 1996 Theo de Raadt
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
 ** loginrec.c:  platform-independent login recording and lastlog retrieval
 **/

/*
 *  The new login code explained
 *  ============================
 *
 *  This code attempts to provide a common interface to login recording
 *  (utmp and friends) and last login time retrieval.
 *
 *  Its primary means of achieving this is to use 'struct logininfo', a
 *  union of all the useful fields in the various different types of
 *  system login record structures one finds on UNIX variants.
 *
 *  We depend on autoconf to define which recording methods are to be
 *  used, and which fields are contained in the relevant data structures
 *  on the local system. Many C preprocessor symbols affect which code
 *  gets compiled here.
 *
 *  The code is designed to make it easy to modify a particular
 *  recording method, without affecting other methods nor requiring so
 *  many nested conditional compilation blocks as were commonplace in
 *  the old code.
 *
 *  For login recording, we try to use the local system's libraries as
 *  these are clearly most likely to work correctly. For utmp systems
 *  this usually means login() and logout() or setutent() etc., probably
 *  in libutil, along with logwtmp() etc. On these systems, we fall back
 *  to writing the files directly if we have to, though this method
 *  requires very thorough testing so we do not corrupt local auditing
 *  information. These files and their access methods are very system
 *  specific indeed.
 *
 *  For utmpx systems, the corresponding library functions are
 *  setutxent() etc. To the author's knowledge, all utmpx systems have
 *  these library functions and so no direct write is attempted. If such
 *  a system exists and needs support, direct analogues of the [uw]tmp
 *  code should suffice.
 *
 *  Retrieving the time of last login ('lastlog') is in some ways even
 *  more problematic than login recording. Some systems provide a
 *  simple table of all users which we seek based on uid and retrieve a
 *  relatively standard structure. Others record the same information in
 *  a directory with a separate file, and others don't record the
 *  information separately at all. For systems in the latter category,
 *  we look backwards in the wtmp or wtmpx file for the last login entry
 *  for our user. Naturally this is slower and on busy systems could
 *  incur a significant performance penalty.
 *
 *  Calling the new code
 *  --------------------
 *
 *  In OpenSSH all login recording and retrieval is performed in
 *  login.c. Here you'll find working examples. Also, in the logintest.c
 *  program there are more examples.
 *
 *  Internal handler calling method
 *  -------------------------------
 *
 *  When a call is made to login_login() or login_logout(), both
 *  routines set a struct logininfo flag defining which action (log in,
 *  or log out) is to be taken. They both then call login_write(), which
 *  calls whichever of the many structure-specific handlers autoconf
 *  selects for the local system.
 *
 *  The handlers themselves handle system data structure specifics. Both
 *  struct utmp and struct utmpx have utility functions (see
 *  construct_utmp*()) to try to make it simpler to add extra systems
 *  that introduce new features to either structure.
 *
 *  While it may seem terribly wasteful to replicate so much similar
 *  code for each method, experience has shown that maintaining code to
 *  write both struct utmp and utmpx in one function, whilst maintaining
 *  support for all systems whether they have library support or not, is
 *  a difficult and time-consuming task.
 *
 *  Lastlog support proceeds similarly. Functions login_get_lastlog()
 *  (and its OpenSSH-tuned friend login_get_lastlog_time()) call
 *  getlast_entry(), which tries one of three methods to find the last
 *  login time. It uses local system lastlog support if it can,
 *  otherwise it tries wtmp or wtmpx before giving up and returning 0,
 *  meaning "tilt".
 *
 *  Maintenance
 *  -----------
 *
 *  In many cases it's possible to tweak autoconf to select the correct
 *  methods for a particular platform, either by improving the detection
 *  code (best), or by presetting DISABLE_<method> or CONF_<method>_FILE
 *  symbols for the platform.
 *
 *  Use logintest to check which symbols are defined before modifying
 *  configure.ac and loginrec.c. (You have to build logintest yourself
 *  with 'make logintest' as it's not built by default.)
 *
 *  Otherwise, patches to the specific method(s) are very helpful!
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "loginrec.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

# include <util.h>

#ifdef USE_WTMPDB
# include <wtmpdb.h>
#endif

/**
 ** prototypes for helper functions in this file
 **/

#ಯದಿ HAVE_UTMP_H
ಶೂನ್ಯ set_utmp_time(ಸಂರಚನಾ logininfo *li, ಸಂರಚನಾ utmp *ut);
ಶೂನ್ಯ construct_utmp(ಸಂರಚನಾ logininfo *li, ಸಂರಚನಾ utmp *ut);
#endif

#ifdef HAVE_UTMPX_H
ಶೂನ್ಯ set_utmpx_time(ಸಂರಚನಾ logininfo *li, ಸಂರಚನಾ utmpx *ut);
ಶೂನ್ಯ construct_utmpx(ಸಂರಚನಾ logininfo *li, ಸಂರಚನಾ utmpx *ut);
#endif

ಪೂರ್ಣಾಙ್ಕ utmp_write_entry(ಸಂರಚನಾ logininfo *li);
ಪೂರ್ಣಾಙ್ಕ utmpx_write_entry(ಸಂರಚನಾ logininfo *li);
ಪೂರ್ಣಾಙ್ಕ wtmp_write_entry(ಸಂರಚನಾ logininfo *li);
ಪೂರ್ಣಾಙ್ಕ wtmpx_write_entry(ಸಂರಚನಾ logininfo *li);
ಪೂರ್ಣಾಙ್ಕ lastlog_write_entry(ಸಂರಚನಾ logininfo *li);
ಪೂರ್ಣಾಙ್ಕ syslogin_write_entry(ಸಂರಚನಾ logininfo *li);
#ifdef USE_WTMPDB
ಪೂರ್ಣಾಙ್ಕ wtmpdb_write_entry(ಸಂರಚನಾ logininfo *li);
#endif

ಪೂರ್ಣಾಙ್ಕ getlast_entry(ಸಂರಚನಾ logininfo *li);
ಪೂರ್ಣಾಙ್ಕ lastlog_get_entry(ಸಂರಚನಾ logininfo *li);
ಪೂರ್ಣಾಙ್ಕ utmpx_get_entry(ಸಂರಚನಾ logininfo *li);
ಪೂರ್ಣಾಙ್ಕ wtmp_get_entry(ಸಂರಚನಾ logininfo *li);
ಪೂರ್ಣಾಙ್ಕ wtmpx_get_entry(ಸಂರಚನಾ logininfo *li);

ಬಾಹ್ಯ ಸಂರಚನಾ sshbuf *loginmsg;

/* pick the shortest string */
#define MIN_SIZEOF(s1,s2) (ಪರಿಮಾಣ(s1) < ಪರಿಮಾಣ(s2) ? ಪರಿಮಾಣ(s1) : ಪರಿಮಾಣ(s2))

/**
 ** platform-independent login functions
 **/

/*
 * login_login(struct logininfo *) - Record a login
 *
 * Call with a pointer to a struct logininfo initialised with
 * login_init_entry() or login_alloc_entry()
 *
 * Returns:
 *  >0 if successful
 *  0  on failure (will use OpenSSH's logging facilities for diagnostics)
 */
ಪೂರ್ಣಾಙ್ಕ
login_login(ಸಂರಚನಾ logininfo *li)
{
	li->type = LTYPE_LOGIN;
	ಪ್ರತ್ಯಾಗಮ (login_write(li));
}


/*
 * login_logout(struct logininfo *) - Record a logout
 *
 * Call as with login_login()
 *
 * Returns:
 *  >0 if successful
 *  0  on failure (will use OpenSSH's logging facilities for diagnostics)
 */
ಪೂರ್ಣಾಙ್ಕ
login_logout(ಸಂರಚನಾ logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	ಪ್ರತ್ಯಾಗಮ (login_write(li));
}

/*
 * login_get_lastlog_time(int) - Retrieve the last login time
 *
 * Retrieve the last login time for the given uid. Will try to use the
 * system lastlog facilities if they are available, but will fall back
 * to looking in wtmp/wtmpx if necessary
 *
 * Returns:
 *   0 on failure, or if user has never logged in
 *   Time in seconds from the epoch if successful
 *
 * Useful preprocessor symbols:
 *   DISABLE_LASTLOG: If set, *never* even try to retrieve lastlog
 *                    info
 *   USE_LASTLOG: If set, indicates the presence of system lastlog
 *                facilities. If this and DISABLE_LASTLOG are not set,
 *                try to retrieve lastlog information from wtmp/wtmpx.
 */
unsigned ಪೂರ್ಣಾಙ್ಕ
login_get_lastlog_time(ಧ್ರುವ uid_t uid)
{
	ಸಂರಚನಾ logininfo li;

	ಯದಿ (login_get_lastlog(&li, uid))
		ಪ್ರತ್ಯಾಗಮ (li.tv_sec);
	ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ (0);
}

/*
 * login_get_lastlog(struct logininfo *, int)   - Retrieve a lastlog entry
 *
 * Retrieve a logininfo structure populated (only partially) with
 * information from the system lastlog data, or from wtmp/wtmpx if no
 * system lastlog information exists.
 *
 * Note this routine must be given a pre-allocated logininfo.
 *
 * Returns:
 *  >0: A pointer to your struct logininfo if successful
 *  0  on failure (will use OpenSSH's logging facilities for diagnostics)
 */
ಸಂರಚನಾ logininfo *
login_get_lastlog(ಸಂರಚನಾ logininfo *li, ಧ್ರುವ uid_t uid)
{
	ಸಂರಚನಾ passwd *pw;

	memset(li, '\0', ಪರಿಮಾಣ(*li));
	li->uid = uid;

	/*
	 * If we don't have a 'real' lastlog, we need the username to
	 * reliably search wtmp(x) for the last login (see
	 * wtmp_get_entry().)
	 */
	pw = getpwuid(uid);
	ಯದಿ (pw == ರಿಕ್ತ)
		fatal("%s: Cannot find account for uid %ld", __func__,
		    (long)uid);

	ಯದಿ (strlcpy(li->username, pw->pw_name, ಪರಿಮಾಣ(li->username)) >=
	    ಪರಿಮಾಣ(li->username)) {
		error("%s: username too long (%lu > max %lu)", __func__,
		    (unsigned long)strlen(pw->pw_name),
		    (unsigned long)ಪರಿಮಾಣ(li->username) - 1);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	ಯದಿ (getlast_entry(li))
		ಪ್ರತ್ಯಾಗಮ (li);
	ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
}

/*
 * login_alloc_entry(int, char*, char*, char*)    - Allocate and initialise
 *                                                  a logininfo structure
 *
 * This function creates a new struct logininfo, a data structure
 * meant to carry the information required to portably record login info.
 *
 * Returns a pointer to a newly created struct logininfo. If memory
 * allocation fails, the program halts.
 */
ಸಂರಚನಾ
logininfo *login_alloc_entry(pid_t pid, ಧ್ರುವ ವರ್ಣ *username,
    ಧ್ರುವ ವರ್ಣ *hostname, ಧ್ರುವ ವರ್ಣ *ಸಾಲು)
{
	ಸಂರಚನಾ logininfo *newli;

	newli = xmalloc(ಪರಿಮಾಣ(*newli));
	login_init_entry(newli, pid, username, hostname, ಸಾಲು);
	ಪ್ರತ್ಯಾಗಮ (newli);
}


/* login_free_entry(struct logininfo *)    - free struct memory */
ಶೂನ್ಯ
login_free_entry(ಸಂರಚನಾ logininfo *li)
{
	ಮುಕ್ತ(li);
}


/* login_init_entry(struct logininfo *, int, char*, char*, char*)
 *                                        - initialise a struct logininfo
 *
 * Populates a new struct logininfo, a data structure meant to carry
 * the information required to portably record login info.
 *
 * Returns: 1
 */
ಪೂರ್ಣಾಙ್ಕ
login_init_entry(ಸಂರಚನಾ logininfo *li, pid_t pid, ಧ್ರುವ ವರ್ಣ *username,
    ಧ್ರುವ ವರ್ಣ *hostname, ಧ್ರುವ ವರ್ಣ *ಸಾಲು)
{
	ಸಂರಚನಾ passwd *pw;

	memset(li, 0, ಪರಿಮಾಣ(*li));

	li->pid = pid;

	/* set the line information */
	ಯದಿ (ಸಾಲು)
		ಸಾಲು_fullname(li->ಸಾಲು, ಸಾಲು, ಪರಿಮಾಣ(li->ಸಾಲು));

	ಯದಿ (username) {
		strlcpy(li->username, username, ಪರಿಮಾಣ(li->username));
		pw = getpwnam(li->username);
		ಯದಿ (pw == ರಿಕ್ತ) {
			fatal("%s: Cannot find user \"%s\"", __func__,
			    li->username);
		}
		li->uid = pw->pw_uid;
	}

	ಯದಿ (hostname)
		strlcpy(li->hostname, hostname, ಪರಿಮಾಣ(li->hostname));

	ಪ್ರತ್ಯಾಗಮ (1);
}

/*
 * login_set_current_time(struct logininfo *)    - set the current time
 *
 * Set the current time in a logininfo structure. This function is
 * meant to eliminate the need to deal with system dependencies for
 * time handling.
 */
ಶೂನ್ಯ
login_set_current_time(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ timeval tv;

	gettimeofday(&tv, ರಿಕ್ತ);

	li->tv_sec = tv.tv_sec;
	li->tv_usec = tv.tv_usec;
}

/* copy a sockaddr_* into our logininfo */
ಶೂನ್ಯ
login_set_addr(ಸಂರಚನಾ logininfo *li, ಧ್ರುವ ಸಂರಚನಾ sockaddr *sa,
    ಧ್ರುವ unsigned ಪೂರ್ಣಾಙ್ಕ sa_size)
{
	unsigned ಪೂರ್ಣಾಙ್ಕ bufsize = sa_size;

	/* make sure we don't overrun our union */
	ಯದಿ (ಪರಿಮಾಣ(li->hostaddr) < sa_size)
		bufsize = ಪರಿಮಾಣ(li->hostaddr);

	memcpy(&li->hostaddr.sa, sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/
ಪೂರ್ಣಾಙ್ಕ
login_write(ಸಂರಚನಾ logininfo *li)
{
#ifndef HAVE_CYGWIN
	ಯದಿ (geteuid() != 0) {
		logit("Attempt to write login records by non-root user (aborting)");
		ಪ್ರತ್ಯಾಗಮ (1);
	}
#endif

	/* set the timestamp */
	login_set_current_time(li);
#ifdef USE_LOGIN
	syslogin_write_entry(li);
#endif
#ifdef USE_LASTLOG
	ಯದಿ (li->type == LTYPE_LOGIN)
		lastlog_write_entry(li);
#endif
#ifdef USE_UTMP
	utmp_write_entry(li);
#endif
#ifdef USE_WTMP
	wtmp_write_entry(li);
#endif
#ifdef USE_UTMPX
	utmpx_write_entry(li);
#endif
#ifdef USE_WTMPX
	wtmpx_write_entry(li);
#endif
#ifdef USE_WTMPDB
	wtmpdb_write_entry(li);
#endif
#ifdef CUSTOM_SYS_AUTH_RECORD_LOGIN
	ಯದಿ (li->type == LTYPE_LOGIN &&
	    !sys_auth_record_login(li->username,li->hostname,li->ಸಾಲು,
	    loginmsg))
		logit("Writing login record failed for %s", li->username);
#endif
#ifdef SSH_AUDIT_EVENTS
	ಯದಿ (li->type == LTYPE_LOGIN)
		audit_session_open(li);
	ಅನ್ಯಥಾ ಯದಿ (li->type == LTYPE_LOGOUT)
		audit_session_close(li);
#endif
	ಪ್ರತ್ಯಾಗಮ (0);
}

#ifdef LOGIN_NEEDS_UTMPX
ಪೂರ್ಣಾಙ್ಕ
login_utmp_only(ಸಂರಚನಾ logininfo *li)
{
	li->type = LTYPE_LOGIN;
	login_set_current_time(li);
# ifdef USE_UTMP
	utmp_write_entry(li);
# endif
# ifdef USE_WTMP
	wtmp_write_entry(li);
# endif
# ifdef USE_UTMPX
	utmpx_write_entry(li);
# endif
# ifdef USE_WTMPX
	wtmpx_write_entry(li);
# endif
	ಪ್ರತ್ಯಾಗಮ (0);
}
#endif

/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
ಪೂರ್ಣಾಙ್ಕ
getlast_entry(ಸಂರಚನಾ logininfo *li)
{
#ifdef USE_LASTLOG
	ಪ್ರತ್ಯಾಗಮ(lastlog_get_entry(li));
#ಅನ್ಯಥಾ /* !USE_LASTLOG */
#ಯದಿ defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
	ಪ್ರತ್ಯಾಗಮ (utmpx_get_entry(li));
#endif

#ಯದಿ defined(DISABLE_LASTLOG)
	/* On some systems we shouldn't even try to obtain last login
	 * time, e.g. AIX */
	ಪ್ರತ್ಯಾಗಮ (0);
# elif defined(USE_WTMP) && \
    (defined(HAVE_TIME_IN_UTMP) || defined(HAVE_TV_IN_UTMP))
	/* retrieve last login time from utmp */
	ಪ್ರತ್ಯಾಗಮ (wtmp_get_entry(li));
# elif defined(USE_WTMPX) && \
    (defined(HAVE_TIME_IN_UTMPX) || defined(HAVE_TV_IN_UTMPX))
	/* If wtmp isn't available, try wtmpx */
	ಪ್ರತ್ಯಾಗಮ (wtmpx_get_entry(li));
# ಅನ್ಯಥಾ
	/* Give up: No means of retrieving last login time */
	ಪ್ರತ್ಯಾಗಮ (0);
# endif /* DISABLE_LASTLOG */
#endif /* USE_LASTLOG */
}



/*
 * 'line' string utility functions
 *
 * These functions process the 'line' string into one of three forms:
 *
 * 1. The full filename (including '/dev')
 * 2. The stripped name (excluding '/dev')
 * 3. The abbreviated name (e.g. /dev/ttyp00 -> yp00
 *                               /dev/pts/1  -> ts/1 )
 *
 * Form 3 is used on some systems to identify a .tmp.? entry when
 * attempting to remove it. Typically both addition and removal is
 * performed by one application - say, sshd - so as long as the choice
 * uniquely identifies a terminal it's ok.
 */


/*
 * line_fullname(): add the leading '/dev/' if it doesn't exist make
 * sure dst has enough space, if not just copy src (ugh)
 */
ವರ್ಣ *
ಸಾಲು_fullname(ವರ್ಣ *dst, ಧ್ರುವ ವರ್ಣ *src, u_int dstsize)
{
	memset(dst, '\0', dstsize);
	ಯದಿ ((strncmp(src, "/dev/", 5) == 0) || (dstsize < (strlen(src) + 5)))
		strlcpy(dst, src, dstsize);
	ಅನ್ಯಥಾ {
		strlcpy(dst, "/dev/", dstsize);
		strlcat(dst, src, dstsize);
	}
	ಪ್ರತ್ಯಾಗಮ (dst);
}

/* line_stripname(): strip the leading '/dev' if it exists, return dst */
ವರ್ಣ *
ಸಾಲು_stripname(ವರ್ಣ *dst, ಧ್ರುವ ವರ್ಣ *src, ಪೂರ್ಣಾಙ್ಕ dstsize)
{
	memset(dst, '\0', dstsize);
	ಯದಿ (strncmp(src, "/dev/", 5) == 0)
		strlcpy(dst, src + 5, dstsize);
	ಅನ್ಯಥಾ
		strlcpy(dst, src, dstsize);
	ಪ್ರತ್ಯಾಗಮ (dst);
}

/*
 * line_abbrevname(): Return the abbreviated (usually four-character)
 * form of the line (Just use the last <dstsize> characters of the
 * full name.)
 *
 * NOTE: use strncpy because we do NOT necessarily want zero
 * termination
 */
ವರ್ಣ *
ಸಾಲು_abbrevname(ವರ್ಣ *dst, ಧ್ರುವ ವರ್ಣ *src, ಪೂರ್ಣಾಙ್ಕ dstsize)
{
	size_t len;

	memset(dst, '\0', dstsize);

	ಯದಿ (strcmp(src, "ssh:notty") == 0)
		ಪ್ರತ್ಯಾಗಮ dst;

	/* Always skip prefix if present */
	ಯದಿ (strncmp(src, "/dev/", 5) == 0)
		src += 5;

#ifdef WITH_ABBREV_NO_TTY
	ಯದಿ (strncmp(src, "tty", 3) == 0)
		src += 3;
#endif

	len = strlen(src);

	ಯದಿ (len > 0) {
		ಯದಿ (((ಪೂರ್ಣಾಙ್ಕ)len - dstsize) > 0)
			src +=  ((ಪೂರ್ಣಾಙ್ಕ)len - dstsize);

		/* note: _don't_ change this to strlcpy */
		strncpy(dst, src, (size_t)dstsize);
	}

	ಪ್ರತ್ಯಾಗಮ (dst);
}

/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#ಯದಿ defined(USE_BTMP) || defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
ಶೂನ್ಯ
set_utmp_time(ಸಂರಚನಾ logininfo *li, ಸಂರಚನಾ utmp *ut)
{
# ಯದಿ defined(HAVE_TV_IN_UTMP)
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMP)
	ut->ut_time = li->tv_sec;
# endif
}

ಶೂನ್ಯ
construct_utmp(ಸಂರಚನಾ logininfo *li,
		    ಸಂರಚನಾ utmp *ut)
{
# ifdef HAVE_ADDR_V6_IN_UTMP
	ಸಂರಚನಾ sockaddr_in6 *sa6;
# endif

	memset(ut, '\0', ಪರಿಮಾಣ(*ut));

	/* First fill out fields used for both logins and logouts */

# ifdef HAVE_ID_IN_UTMP
	ಸಾಲು_abbrevname(ut->ut_id, li->ಸಾಲು, ಪರಿಮಾಣ(ut->ut_id));
# endif

# ifdef HAVE_TYPE_IN_UTMP
	/* This is done here to keep utmp constants out of struct logininfo */
	ವಿಕಲ್ಪ (li->type) {
	ಪಕ್ಷ LTYPE_FAILED:
		ut->ut_type = LOGIN_PROCESS;
		ಭಙ್ಗ;
	ಪಕ್ಷ LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		ಭಙ್ಗ;
	ಪಕ್ಷ LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		ಭಙ್ಗ;
	}
# endif
	set_utmp_time(li, ut);

	ಸಾಲು_stripname(ut->ut_ಸಾಲು, li->ಸಾಲು, ಪರಿಮಾಣ(ut->ut_ಸಾಲು));

# ifdef HAVE_PID_IN_UTMP
	ut->ut_pid = li->pid;
# endif

	/* If we're logging out, leave all other fields blank */
	ಯದಿ (li->type == LTYPE_LOGOUT)
		ಪ್ರತ್ಯಾಗಮ;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

	/* Use strncpy because we don't necessarily want null termination */
	strncpy(ut->ut_name, li->username,
	    MIN_SIZEOF(ut->ut_name, li->username));
# ifdef HAVE_HOST_IN_UTMP
	strncpy(ut->ut_host, li->hostname,
	    MIN_SIZEOF(ut->ut_host, li->hostname));
# endif
# ifdef HAVE_ADDR_IN_UTMP
	/* this is just a 32-bit IP address */
	ಯದಿ (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMP
	/* this is just a 128-bit IPv6 address */
	ಯದಿ (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((ಸಂರಚನಾ sockaddr_in6 *)&li->hostaddr.sa);
		memcpy(ut->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		ಯದಿ (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			ut->ut_addr_v6[0] = ut->ut_addr_v6[3];
			ut->ut_addr_v6[1] = 0;
			ut->ut_addr_v6[2] = 0;
			ut->ut_addr_v6[3] = 0;
		}
	}
# endif
}
#endif /* USE_BTMP || USE_UTMP || USE_WTMP || USE_LOGIN */

/**
 ** utmpx utility functions
 **
 ** These functions manipulate struct utmpx, accounting for system
 ** variations.
 **/

#ಯದಿ defined(USE_UTMPX) || defined (USE_WTMPX)
/* build the utmpx structure */
ಶೂನ್ಯ
set_utmpx_time(ಸಂರಚನಾ logininfo *li, ಸಂರಚನಾ utmpx *utx)
{
# ಯದಿ defined(HAVE_TV_IN_UTMPX)
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMPX)
	utx->ut_time = li->tv_sec;
# endif
}

ಶೂನ್ಯ
construct_utmpx(ಸಂರಚನಾ logininfo *li, ಸಂರಚನಾ utmpx *utx)
{
# ifdef HAVE_ADDR_V6_IN_UTMPX
	ಸಂರಚನಾ sockaddr_in6 *sa6;
#  endif
	memset(utx, '\0', ಪರಿಮಾಣ(*utx));

# ifdef HAVE_ID_IN_UTMPX
	ಸಾಲು_abbrevname(utx->ut_id, li->ಸಾಲು, ಪರಿಮಾಣ(utx->ut_id));
# endif

	/* this is done here to keep utmp constants out of loginrec.h */
	ವಿಕಲ್ಪ (li->type) {
	ಪಕ್ಷ LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		ಭಙ್ಗ;
	ಪಕ್ಷ LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		ಭಙ್ಗ;
	}
	ಸಾಲು_stripname(utx->ut_ಸಾಲು, li->ಸಾಲು, ಪರಿಮಾಣ(utx->ut_ಸಾಲು));
	set_utmpx_time(li, utx);
	utx->ut_pid = li->pid;

	/* strncpy(): Don't necessarily want null termination */
	strncpy(utx->ut_user, li->username,
	    MIN_SIZEOF(utx->ut_user, li->username));

	ಯದಿ (li->type == LTYPE_LOGOUT)
		ಪ್ರತ್ಯಾಗಮ;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

# ifdef HAVE_HOST_IN_UTMPX
	strncpy(utx->ut_host, li->hostname,
	    MIN_SIZEOF(utx->ut_host, li->hostname));
# endif
# ifdef HAVE_SS_IN_UTMPX
	utx->ut_ss = li->hostaddr.sa_storage;
# endif
# ifdef HAVE_ADDR_IN_UTMPX
	/* this is just a 32-bit IP address */
	ಯದಿ (li->hostaddr.sa.sa_family == AF_INET)
		utx->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMPX
	/* this is just a 128-bit IPv6 address */
	ಯದಿ (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((ಸಂರಚನಾ sockaddr_in6 *)&li->hostaddr.sa);
		memcpy(utx->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		ಯದಿ (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			utx->ut_addr_v6[0] = utx->ut_addr_v6[3];
			utx->ut_addr_v6[1] = 0;
			utx->ut_addr_v6[2] = 0;
			utx->ut_addr_v6[3] = 0;
		}
	}
# endif
# ifdef HAVE_SYSLEN_IN_UTMPX
	/* ut_syslen is the length of the utx_host string */
	utx->ut_syslen = MINIMUM(strlen(li->hostname), ಪರಿಮಾಣ(utx->ut_host));
# endif
}
#endif /* USE_UTMPX || USE_WTMPX */

/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */
#ifdef USE_UTMP

/* if we can, use pututline() etc. */
# ಯದಿ !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
	defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
# endif


/* write a utmp entry with the system's help (pututline() and pals) */
# ifdef UTMP_USE_LIBRARY
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
utmp_write_library(ಸಂರಚನಾ logininfo *li, ಸಂರಚನಾ utmp *ut)
{
	setutent();
	pututline(ut);
#  ifdef HAVE_ENDUTENT
	endutent();
#  endif
	ಪ್ರತ್ಯಾಗಮ (1);
}
# ಅನ್ಯಥಾ /* UTMP_USE_LIBRARY */

/*
 * Write a utmp entry direct to the file
 * This is a slightly modification of code in OpenBSD's login.c
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
utmp_write_direct(ಸಂರಚನಾ logininfo *li, ಸಂರಚನಾ utmp *ut)
{
	ಸಂರಚನಾ utmp old_ut;
	ಪಞ್ಜಿಕಾ ಪೂರ್ಣಾಙ್ಕ fd;
	ಪೂರ್ಣಾಙ್ಕ tty;

	/* FIXME: (ATL) ttyslot() needs local implementation */

#ಯದಿ defined(HAVE_GETTTYENT)
	ಸಂರಚನಾ ttyent *ty;

	tty=0;
	setttyent();
	ಯಾವತ್ (ರಿಕ್ತ != (ty = getttyent())) {
		tty++;
		ಯದಿ (!strncmp(ty->ty_name, ut->ut_ಸಾಲು, ಪರಿಮಾಣ(ut->ut_ಸಾಲು)))
			ಭಙ್ಗ;
	}
	endttyent();

	ಯದಿ (ರಿಕ್ತ == ty) {
		logit_f("tty not found");
		ಪ್ರತ್ಯಾಗಮ (0);
	}
#ಅನ್ಯಥಾ /* FIXME */

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

#endif /* HAVE_GETTTYENT */

	ಯದಿ (tty > 0 && (fd = open(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		off_t pos, ret;

		pos = (off_t)tty * ಪರಿಮಾಣ(ಸಂರಚನಾ utmp);
		ಯದಿ ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			ಪ್ರತ್ಯಾಗಮ (0);
		}
		ಯದಿ (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			ಪ್ರತ್ಯಾಗಮ (0);
		}
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		ಯದಿ (atomicio(ಪಠ, fd, &old_ut, ಪರಿಮಾಣ(old_ut)) == ಪರಿಮಾಣ(old_ut) &&
		    (ut->ut_host[0] == '\0') && (old_ut.ut_host[0] != '\0') &&
		    (strncmp(old_ut.ut_ಸಾಲು, ut->ut_ಸಾಲು, ಪರಿಮಾಣ(ut->ut_ಸಾಲು)) == 0) &&
		    (strncmp(old_ut.ut_name, ut->ut_name, ಪರಿಮಾಣ(ut->ut_name)) == 0))
			memcpy(ut->ut_host, old_ut.ut_host, ಪರಿಮಾಣ(ut->ut_host));

		ಯದಿ ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			ಪ್ರತ್ಯಾಗಮ (0);
		}
		ಯದಿ (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			ಪ್ರತ್ಯಾಗಮ (0);
		}
		ಯದಿ (atomicio(vwrite, fd, ut, ಪರಿಮಾಣ(*ut)) != ಪರಿಮಾಣ(*ut)) {
			logit("%s: error writing %s: %s", __func__,
			    UTMP_FILE, strerror(errno));
			close(fd);
			ಪ್ರತ್ಯಾಗಮ (0);
		}

		close(fd);
		ಪ್ರತ್ಯಾಗಮ (1);
	} ಅನ್ಯಥಾ {
		ಪ್ರತ್ಯಾಗಮ (0);
	}
}
# endif /* UTMP_USE_LIBRARY */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
utmp_perform_login(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	ಯದಿ (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		ಪ್ರತ್ಯಾಗಮ (0);
	}
# ಅನ್ಯಥಾ
	ಯದಿ (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		ಪ್ರತ್ಯಾಗಮ (0);
	}
# endif
	ಪ್ರತ್ಯಾಗಮ (1);
}


ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
utmp_perform_logout(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	ಯದಿ (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		ಪ್ರತ್ಯಾಗಮ (0);
	}
# ಅನ್ಯಥಾ
	ಯದಿ (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		ಪ್ರತ್ಯಾಗಮ (0);
	}
# endif
	ಪ್ರತ್ಯಾಗಮ (1);
}


ಪೂರ್ಣಾಙ್ಕ
utmp_write_entry(ಸಂರಚನಾ logininfo *li)
{
	ವಿಕಲ್ಪ(li->type) {
	ಪಕ್ಷ LTYPE_LOGIN:
		ಪ್ರತ್ಯಾಗಮ (utmp_perform_login(li));

	ಪಕ್ಷ LTYPE_LOGOUT:
		ಪ್ರತ್ಯಾಗಮ (utmp_perform_logout(li));

	ಸ್ವಭಾವ:
		logit_f("invalid type field");
		ಪ್ರತ್ಯಾಗಮ (0);
	}
}
#endif /* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#ifdef USE_UTMPX

/* if we have the wherewithal, use pututxline etc. */
# ಯದಿ !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) && \
	defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
# endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
# ifdef UTMPX_USE_LIBRARY
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
utmpx_write_library(ಸಂರಚನಾ logininfo *li, ಸಂರಚನಾ utmpx *utx)
{
	setutxent();
	pututxline(utx);

#  ifdef HAVE_ENDUTXENT
	endutxent();
#  endif
	ಪ್ರತ್ಯಾಗಮ (1);
}

# ಅನ್ಯಥಾ /* UTMPX_USE_LIBRARY */

/* write a utmp entry direct to the file */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
utmpx_write_direct(ಸಂರಚನಾ logininfo *li, ಸಂರಚನಾ utmpx *utx)
{
	logit_f("not implemented!");
	ಪ್ರತ್ಯಾಗಮ (0);
}
# endif /* UTMPX_USE_LIBRARY */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
utmpx_perform_login(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ utmpx utx;

	construct_utmpx(li, &utx);
# ifdef UTMPX_USE_LIBRARY
	ಯದಿ (!utmpx_write_library(li, &utx)) {
		logit_f("utmp_write_library() failed");
		ಪ್ರತ್ಯಾಗಮ (0);
	}
# ಅನ್ಯಥಾ
	ಯದಿ (!utmpx_write_direct(li, &utx)) {
		logit_f("utmp_write_direct() failed");
		ಪ್ರತ್ಯಾಗಮ (0);
	}
# endif
	ಪ್ರತ್ಯಾಗಮ (1);
}


ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
utmpx_perform_logout(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ utmpx utx;

	construct_utmpx(li, &utx);
# ifdef HAVE_ID_IN_UTMPX
	ಸಾಲು_abbrevname(utx.ut_id, li->ಸಾಲು, ಪರಿಮಾಣ(utx.ut_id));
# endif
# ifdef HAVE_TYPE_IN_UTMPX
	utx.ut_type = DEAD_PROCESS;
# endif

# ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
# ಅನ್ಯಥಾ
	utmpx_write_direct(li, &utx);
# endif
	ಪ್ರತ್ಯಾಗಮ (1);
}

ಪೂರ್ಣಾಙ್ಕ
utmpx_write_entry(ಸಂರಚನಾ logininfo *li)
{
	ವಿಕಲ್ಪ(li->type) {
	ಪಕ್ಷ LTYPE_LOGIN:
		ಪ್ರತ್ಯಾಗಮ (utmpx_perform_login(li));
	ಪಕ್ಷ LTYPE_LOGOUT:
		ಪ್ರತ್ಯಾಗಮ (utmpx_perform_logout(li));
	ಸ್ವಭಾವ:
		logit_f("invalid type field");
		ಪ್ರತ್ಯಾಗಮ (0);
	}
}
#endif /* USE_UTMPX */


/**
 ** Low-level wtmp functions
 **/

#ifdef USE_WTMP

/*
 * Write a wtmp entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
wtmp_write(ಸಂರಚನಾ logininfo *li, ಸಂರಚನಾ utmp *ut)
{
	ಸಂರಚನಾ stat buf;
	ಪೂರ್ಣಾಙ್ಕ fd, ret = 1;

	ಯದಿ ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem writing %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ (0);
	}
	ಯದಿ (fstat(fd, &buf) == 0)
		ಯದಿ (atomicio(vwrite, fd, ut, ಪರಿಮಾಣ(*ut)) != ಪರಿಮಾಣ(*ut)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMP_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);
	ಪ್ರತ್ಯಾಗಮ (ret);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
wtmp_perform_login(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ utmp ut;

	construct_utmp(li, &ut);
	ಪ್ರತ್ಯಾಗಮ (wtmp_write(li, &ut));
}


ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
wtmp_perform_logout(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ utmp ut;

	construct_utmp(li, &ut);
	ಪ್ರತ್ಯಾಗಮ (wtmp_write(li, &ut));
}


ಪೂರ್ಣಾಙ್ಕ
wtmp_write_entry(ಸಂರಚನಾ logininfo *li)
{
	ವಿಕಲ್ಪ(li->type) {
	ಪಕ್ಷ LTYPE_LOGIN:
		ಪ್ರತ್ಯಾಗಮ (wtmp_perform_login(li));
	ಪಕ್ಷ LTYPE_LOGOUT:
		ಪ್ರತ್ಯಾಗಮ (wtmp_perform_logout(li));
	ಸ್ವಭಾವ:
		logit_f("invalid type field");
		ಪ್ರತ್ಯಾಗಮ (0);
	}
}


/*
 * Notes on fetching login data from wtmp/wtmpx
 *
 * Logouts are usually recorded with (amongst other things) a blank
 * username on a given tty line.  However, some systems (HP-UX is one)
 * leave all fields set, but change the ut_type field to DEAD_PROCESS.
 *
 * Since we're only looking for logins here, we know that the username
 * must be set correctly. On systems that leave it in, we check for
 * ut_type==USER_PROCESS (indicating a login.)
 *
 * Portability: Some systems may set something other than USER_PROCESS
 * to indicate a login process. I don't know of any as I write. Also,
 * it's possible that some systems may both leave the username in
 * place and not have ut_type.
 */

/* return true if this wtmp entry indicates a login */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
wtmp_islogin(ಸಂರಚನಾ logininfo *li, ಸಂರಚನಾ utmp *ut)
{
	ಯದಿ (strncmp(li->username, ut->ut_name,
	    MIN_SIZEOF(li->username, ut->ut_name)) == 0) {
# ifdef HAVE_TYPE_IN_UTMP
		ಯದಿ (ut->ut_type & USER_PROCESS)
			ಪ್ರತ್ಯಾಗಮ (1);
# ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ (1);
# endif
	}
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
wtmp_get_entry(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ stat st;
	ಸಂರಚನಾ utmp ut;
	ಪೂರ್ಣಾಙ್ಕ fd, found = 0;

	/* Clear the time entries in our logininfo */
	li->tv_sec = li->tv_usec = 0;

	ಯದಿ ((fd = open(WTMP_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ (0);
	}
	ಯದಿ (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		close(fd);
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	/* Seek to the start of the last struct utmp */
	ಯದಿ (lseek(fd, -(off_t)ಪರಿಮಾಣ(ಸಂರಚನಾ utmp), SEEK_END) == -1) {
		/* Looks like we've got a fresh wtmp file */
		close(fd);
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	ಯಾವತ್ (!found) {
		ಯದಿ (atomicio(ಪಠ, fd, &ut, ಪರಿಮಾಣ(ut)) != ಪರಿಮಾಣ(ut)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMP_FILE, strerror(errno));
			close (fd);
			ಪ್ರತ್ಯಾಗಮ (0);
		}
		ಯದಿ (wtmp_islogin(li, &ut) ) {
			found = 1;
			/*
			 * We've already checked for a time in struct
			 * utmp, in login_getlast()
			 */
# ifdef HAVE_TIME_IN_UTMP
			li->tv_sec = ut.ut_time;
# ಅನ್ಯಥಾ
#  ಯದಿ HAVE_TV_IN_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
# endif
			ಸಾಲು_fullname(li->ಸಾಲು, ut.ut_ಸಾಲು,
			    MIN_SIZEOF(li->ಸಾಲು, ut.ut_ಸಾಲು));
# ifdef HAVE_HOST_IN_UTMP
			strlcpy(li->hostname, ut.ut_host,
			    MIN_SIZEOF(li->hostname, ut.ut_host));
# endif
			ಅನುವರ್ತ;
		}
		/* Seek back 2 x struct utmp */
		ಯದಿ (lseek(fd, -(off_t)(2 * ಪರಿಮಾಣ(ಸಂರಚನಾ utmp)), SEEK_CUR) == -1) {
			/* We've found the start of the file, so quit */
			close(fd);
			ಪ್ರತ್ಯಾಗಮ (0);
		}
	}

	/* We found an entry. Tidy up and return */
	close(fd);
	ಪ್ರತ್ಯಾಗಮ (1);
}
# endif /* USE_WTMP */


/**
 ** Low-level wtmpx functions
 **/

#ifdef USE_WTMPX
/*
 * Write a wtmpx entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
wtmpx_write(ಸಂರಚನಾ logininfo *li, ಸಂರಚನಾ utmpx *utx)
{
#ifndef HAVE_UPDWTMPX
	ಸಂರಚನಾ stat buf;
	ಪೂರ್ಣಾಙ್ಕ fd, ret = 1;

	ಯದಿ ((fd = open(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	ಯದಿ (fstat(fd, &buf) == 0)
		ಯದಿ (atomicio(vwrite, fd, utx, ಪರಿಮಾಣ(*utx)) != ಪರಿಮಾಣ(*utx)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);

	ಪ್ರತ್ಯಾಗಮ (ret);
#ಅನ್ಯಥಾ
	updwtmpx(WTMPX_FILE, utx);
	ಪ್ರತ್ಯಾಗಮ (1);
#endif
}


ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
wtmpx_perform_login(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ utmpx utx;

	construct_utmpx(li, &utx);
	ಪ್ರತ್ಯಾಗಮ (wtmpx_write(li, &utx));
}


ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
wtmpx_perform_logout(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ utmpx utx;

	construct_utmpx(li, &utx);
	ಪ್ರತ್ಯಾಗಮ (wtmpx_write(li, &utx));
}


ಪೂರ್ಣಾಙ್ಕ
wtmpx_write_entry(ಸಂರಚನಾ logininfo *li)
{
	ವಿಕಲ್ಪ(li->type) {
	ಪಕ್ಷ LTYPE_LOGIN:
		ಪ್ರತ್ಯಾಗಮ (wtmpx_perform_login(li));
	ಪಕ್ಷ LTYPE_LOGOUT:
		ಪ್ರತ್ಯಾಗಮ (wtmpx_perform_logout(li));
	ಸ್ವಭಾವ:
		logit_f("invalid type field");
		ಪ್ರತ್ಯಾಗಮ (0);
	}
}

/* Please see the notes above wtmp_islogin() for information about the
   next two functions */

/* Return true if this wtmpx entry indicates a login */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
wtmpx_islogin(ಸಂರಚನಾ logininfo *li, ಸಂರಚನಾ utmpx *utx)
{
	ಯದಿ (strncmp(li->username, utx->ut_user,
	    MIN_SIZEOF(li->username, utx->ut_user)) == 0 ) {
# ifdef HAVE_TYPE_IN_UTMPX
		ಯದಿ (utx->ut_type == USER_PROCESS)
			ಪ್ರತ್ಯಾಗಮ (1);
# ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ (1);
# endif
	}
	ಪ್ರತ್ಯಾಗಮ (0);
}


ಪೂರ್ಣಾಙ್ಕ
wtmpx_get_entry(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ stat st;
	ಸಂರಚನಾ utmpx utx;
	ಪೂರ್ಣಾಙ್ಕ fd, found=0;

	/* Clear the time entries */
	li->tv_sec = li->tv_usec = 0;

	ಯದಿ ((fd = open(WTMPX_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ (0);
	}
	ಯದಿ (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		close(fd);
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	/* Seek to the start of the last struct utmpx */
	ಯದಿ (lseek(fd, -(off_t)ಪರಿಮಾಣ(ಸಂರಚನಾ utmpx), SEEK_END) == -1 ) {
		/* probably a newly rotated wtmpx file */
		close(fd);
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	ಯಾವತ್ (!found) {
		ಯದಿ (atomicio(ಪಠ, fd, &utx, ಪರಿಮಾಣ(utx)) != ಪರಿಮಾಣ(utx)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			close (fd);
			ಪ್ರತ್ಯಾಗಮ (0);
		}
		/*
		 * Logouts are recorded as a blank username on a particular
		 * line. So, we just need to find the username in struct utmpx
		 */
		ಯದಿ (wtmpx_islogin(li, &utx)) {
			found = 1;
# ಯದಿ defined(HAVE_TV_IN_UTMPX)
			li->tv_sec = utx.ut_tv.tv_sec;
# elif defined(HAVE_TIME_IN_UTMPX)
			li->tv_sec = utx.ut_time;
# endif
			ಸಾಲು_fullname(li->ಸಾಲು, utx.ut_ಸಾಲು, ಪರಿಮಾಣ(li->ಸಾಲು));
# ಯದಿ defined(HAVE_HOST_IN_UTMPX)
			strlcpy(li->hostname, utx.ut_host,
			    MIN_SIZEOF(li->hostname, utx.ut_host));
# endif
			ಅನುವರ್ತ;
		}
		ಯದಿ (lseek(fd, -(off_t)(2 * ಪರಿಮಾಣ(ಸಂರಚನಾ utmpx)), SEEK_CUR) == -1) {
			close(fd);
			ಪ್ರತ್ಯಾಗಮ (0);
		}
	}

	close(fd);
	ಪ್ರತ್ಯಾಗಮ (1);
}
#endif /* USE_WTMPX */

#ifdef USE_WTMPDB
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
wtmpdb_perform_login(ಸಂರಚನಾ logininfo *li)
{
	uint64_t login_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	    li->tv_usec;
	ಧ್ರುವ ವರ್ಣ *tty;

	ಯದಿ (strncmp(li->ಸಾಲು, "/dev/", 5) == 0)
		tty = &(li->ಸಾಲು[5]);
	ಅನ್ಯಥಾ
		tty = li->ಸಾಲು;

	li->wtmpdb_id = wtmpdb_login(ರಿಕ್ತ, USER_PROCESS, li->username,
	    login_time, tty, li->hostname, 0, 0);

	ಯದಿ (li->wtmpdb_id < 0)
		ಪ್ರತ್ಯಾಗಮ (0);

	ಪ್ರತ್ಯಾಗಮ (1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
wtmpdb_perform_logout(ಸಂರಚನಾ logininfo *li)
{
	uint64_t logout_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	   li->tv_usec;

	ಯದಿ (li->wtmpdb_id == 0) {
		ಧ್ರುವ ವರ್ಣ *tty;

		ಯದಿ (strncmp(li->ಸಾಲು, "/dev/", 5) == 0)
			tty = &(li->ಸಾಲು[5]);
		ಅನ್ಯಥಾ
			tty = li->ಸಾಲು;

		li->wtmpdb_id = wtmpdb_get_id(ರಿಕ್ತ, tty, ರಿಕ್ತ);
	}
	wtmpdb_logout(ರಿಕ್ತ, li->wtmpdb_id, logout_time, ರಿಕ್ತ);

	ಪ್ರತ್ಯಾಗಮ (1);
}

ಪೂರ್ಣಾಙ್ಕ
wtmpdb_write_entry(ಸಂರಚನಾ logininfo *li)
{
	ವಿಕಲ್ಪ(li->type) {
	ಪಕ್ಷ LTYPE_LOGIN:
		ಪ್ರತ್ಯಾಗಮ (wtmpdb_perform_login(li));
	ಪಕ್ಷ LTYPE_LOGOUT:
		ಪ್ರತ್ಯಾಗಮ (wtmpdb_perform_logout(li));
	ಸ್ವಭಾವ:
		logit_f("invalid type field");
		ಪ್ರತ್ಯಾಗಮ (0);
	}
}
#endif

/**
 ** Low-level libutil login() functions
 **/

#ifdef USE_LOGIN
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
syslogin_perform_login(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ utmp *ut;

	ut = xmalloc(ಪರಿಮಾಣ(*ut));
	construct_utmp(li, ut);
	login(ut);
	ಮುಕ್ತ(ut);

	ಪ್ರತ್ಯಾಗಮ (1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
syslogin_perform_logout(ಸಂರಚನಾ logininfo *li)
{
# ifdef HAVE_LOGOUT
	ವರ್ಣ ಸಾಲು[UT_LINESIZE];

	(ಶೂನ್ಯ)ಸಾಲು_stripname(ಸಾಲು, li->ಸಾಲು, ಪರಿಮಾಣ(ಸಾಲು));

	ಯದಿ (!logout(ಸಾಲು))
		logit_f("logout() returned an error");
#  ifdef HAVE_LOGWTMP
	ಅನ್ಯಥಾ
		logwtmp(ಸಾಲು, "", "");
#  endif
	/* FIXME: (ATL - if the need arises) What to do if we have
	 * login, but no logout?  what if logout but no logwtmp? All
	 * routines are in libutil so they should all be there,
	 * but... */
# endif
	ಪ್ರತ್ಯಾಗಮ (1);
}

ಪೂರ್ಣಾಙ್ಕ
syslogin_write_entry(ಸಂರಚನಾ logininfo *li)
{
	ವಿಕಲ್ಪ (li->type) {
	ಪಕ್ಷ LTYPE_LOGIN:
		ಪ್ರತ್ಯಾಗಮ (syslogin_perform_login(li));
	ಪಕ್ಷ LTYPE_LOGOUT:
		ಪ್ರತ್ಯಾಗಮ (syslogin_perform_logout(li));
	ಸ್ವಭಾವ:
		logit_f("Invalid type field");
		ಪ್ರತ್ಯಾಗಮ (0);
	}
}
#endif /* USE_LOGIN */

/* end of file log-syslogin.c */

/**
 ** Low-level lastlog functions
 **/

#ifdef USE_LASTLOG

#ಯದಿ !defined(LASTLOG_WRITE_PUTUTXLINE) || !defined(HAVE_GETLASTLOGXBYNAME)
/* open the file (using filemode) and seek to the login entry */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
lastlog_openseek(ಸಂರಚನಾ logininfo *li, ಪೂರ್ಣಾಙ್ಕ *fd, ಪೂರ್ಣಾಙ್ಕ filemode)
{
	off_t offset;
	ವರ್ಣ lastlog_file[1024];
	ಸಂರಚನಾ stat st;

	ಯದಿ (stat(LASTLOG_FILE, &st) != 0) {
		logit("%s: Couldn't stat %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ (0);
	}
	ಯದಿ (S_ISDIR(st.st_mode)) {
		snprintf(lastlog_file, ಪರಿಮಾಣ(lastlog_file), "%s/%s",
		    LASTLOG_FILE, li->username);
	} ಅನ್ಯಥಾ ಯದಿ (S_ISREG(st.st_mode)) {
		strlcpy(lastlog_file, LASTLOG_FILE, ಪರಿಮಾಣ(lastlog_file));
	} ಅನ್ಯಥಾ {
		logit("%s: %.100s is not a file or directory!", __func__,
		    LASTLOG_FILE);
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	*fd = open(lastlog_file, filemode, 0600);
	ಯದಿ (*fd < 0) {
		debug("%s: Couldn't open %s: %s", __func__,
		    lastlog_file, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	ಯದಿ (S_ISREG(st.st_mode)) {
		/* find this uid's offset in the lastlog file */
		offset = (off_t) ((u_long)li->uid * ಪರಿಮಾಣ(ಸಂರಚನಾ lastlog));

		ಯದಿ (lseek(*fd, offset, SEEK_SET) != offset) {
			logit("%s: %s->lseek(): %s", __func__,
			    lastlog_file, strerror(errno));
			close(*fd);
			ಪ್ರತ್ಯಾಗಮ (0);
		}
	}

	ಪ್ರತ್ಯಾಗಮ (1);
}
#endif /* !LASTLOG_WRITE_PUTUTXLINE || !HAVE_GETLASTLOGXBYNAME */

#ifdef LASTLOG_WRITE_PUTUTXLINE
ಪೂರ್ಣಾಙ್ಕ
lastlog_write_entry(ಸಂರಚನಾ logininfo *li)
{
	ವಿಕಲ್ಪ(li->type) {
	ಪಕ್ಷ LTYPE_LOGIN:
		ಪ್ರತ್ಯಾಗಮ 1; /* lastlog written by pututxline */
	ಸ್ವಭಾವ:
		logit("lastlog_write_entry: Invalid type field");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
}
#ಅನ್ಯಥಾ /* LASTLOG_WRITE_PUTUTXLINE */
ಪೂರ್ಣಾಙ್ಕ
lastlog_write_entry(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ lastlog last;
	ಪೂರ್ಣಾಙ್ಕ fd;

	ವಿಕಲ್ಪ(li->type) {
	ಪಕ್ಷ LTYPE_LOGIN:
		/* create our struct lastlog */
		memset(&last, '\0', ಪರಿಮಾಣ(last));
		ಸಾಲು_stripname(last.ll_ಸಾಲು, li->ಸಾಲು, ಪರಿಮಾಣ(last.ll_ಸಾಲು));
		strlcpy(last.ll_host, li->hostname,
		    MIN_SIZEOF(last.ll_host, li->hostname));
		last.ll_time = li->tv_sec;

		ಯದಿ (!lastlog_openseek(li, &fd, O_RDWR|O_CREAT))
			ಪ್ರತ್ಯಾಗಮ (0);

		/* write the entry */
		ಯದಿ (atomicio(vwrite, fd, &last, ಪರಿಮಾಣ(last)) != ಪರಿಮಾಣ(last)) {
			close(fd);
			logit("%s: Error writing to %s: %s", __func__,
			    LASTLOG_FILE, strerror(errno));
			ಪ್ರತ್ಯಾಗಮ (0);
		}

		close(fd);
		ಪ್ರತ್ಯಾಗಮ (1);
	ಸ್ವಭಾವ:
		logit_f("Invalid type field");
		ಪ್ರತ್ಯಾಗಮ (0);
	}
}
#endif /* LASTLOG_WRITE_PUTUTXLINE */

#ifdef HAVE_GETLASTLOGXBYNAME
ಪೂರ್ಣಾಙ್ಕ
lastlog_get_entry(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ lastlogx l, *ll;

	ಯದಿ ((ll = getlastlogxbyname(li->username, &l)) == ರಿಕ್ತ) {
		memset(&l, '\0', ಪರಿಮಾಣ(l));
		ll = &l;
	}
	ಸಾಲು_fullname(li->ಸಾಲು, ll->ll_ಸಾಲು, ಪರಿಮಾಣ(li->ಸಾಲು));
	strlcpy(li->hostname, ll->ll_host,
		MIN_SIZEOF(li->hostname, ll->ll_host));
	li->tv_sec = ll->ll_tv.tv_sec;
	li->tv_usec = ll->ll_tv.tv_usec;
	ಪ್ರತ್ಯಾಗಮ (1);
}
#ಅನ್ಯಥಾ /* HAVE_GETLASTLOGXBYNAME */
ಪೂರ್ಣಾಙ್ಕ
lastlog_get_entry(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ lastlog last;
	ಪೂರ್ಣಾಙ್ಕ fd, ret;

	ಯದಿ (!lastlog_openseek(li, &fd, O_RDONLY))
		ಪ್ರತ್ಯಾಗಮ (0);

	ret = atomicio(ಪಠ, fd, &last, ಪರಿಮಾಣ(last));
	close(fd);

	ವಿಕಲ್ಪ (ret) {
	ಪಕ್ಷ 0:
		memset(&last, '\0', ಪರಿಮಾಣ(last));
		/* FALLTHRU */
	ಪಕ್ಷ ಪರಿಮಾಣ(last):
		ಸಾಲು_fullname(li->ಸಾಲು, last.ll_ಸಾಲು, ಪರಿಮಾಣ(li->ಸಾಲು));
		strlcpy(li->hostname, last.ll_host,
		    MIN_SIZEOF(li->hostname, last.ll_host));
		li->tv_sec = last.ll_time;
		ಪ್ರತ್ಯಾಗಮ (1);
	ಪಕ್ಷ -1:
		error("%s: Error reading from %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ (0);
	ಸ್ವಭಾವ:
		error("%s: Error reading from %s: Expecting %d, got %d",
		    __func__, LASTLOG_FILE, (ಪೂರ್ಣಾಙ್ಕ)ಪರಿಮಾಣ(last), ret);
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	/* NOTREACHED */
	ಪ್ರತ್ಯಾಗಮ (0);
}
#endif /* HAVE_GETLASTLOGXBYNAME */
#endif /* USE_LASTLOG */

#ಯದಿ defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
ಪೂರ್ಣಾಙ್ಕ
utmpx_get_entry(ಸಂರಚನಾ logininfo *li)
{
	ಸಂರಚನಾ utmpx *utx;

	ಯದಿ (setutxdb(UTXDB_LASTLOGIN, ರಿಕ್ತ) != 0)
		ಪ್ರತ್ಯಾಗಮ (0);
	utx = getutxuser(li->username);
	ಯದಿ (utx == ರಿಕ್ತ) {
		endutxent();
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	ಸಾಲು_fullname(li->ಸಾಲು, utx->ut_ಸಾಲು,
	    MIN_SIZEOF(li->ಸಾಲು, utx->ut_ಸಾಲು));
	strlcpy(li->hostname, utx->ut_host,
	    MIN_SIZEOF(li->hostname, utx->ut_host));
	li->tv_sec = utx->ut_tv.tv_sec;
	li->tv_usec = utx->ut_tv.tv_usec;
	endutxent();
	ಪ್ರತ್ಯಾಗಮ (1);
}
#endif /* USE_UTMPX && HAVE_SETUTXDB && UTXDB_LASTLOGIN && HAVE_GETUTXUSER */

#ifdef USE_BTMP
/*
 * Logs failed login attempts in _PATH_BTMP if that exists.
 * The most common login failure is to give password instead of username.
 * So the _PATH_BTMP file is checked for the correct permission, so that only
 * root can read it.
 */
ಶೂನ್ಯ
record_failed_login(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *username, ಧ್ರುವ ವರ್ಣ *hostname,
    ಧ್ರುವ ವರ್ಣ *ttyn)
{
	ಪೂರ್ಣಾಙ್ಕ fd;
	ಸಂರಚನಾ utmp ut;
	ಸಂರಚನಾ logininfo li;
	socklen_t fromlen = ಪರಿಮಾಣ(li.hostaddr);
	time_t t;
	ಸಂರಚನಾ stat fst;

	ಯದಿ (geteuid() != 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ ((fd = open(_PATH_BTMP, O_WRONLY | O_APPEND)) < 0) {
		debug("Unable to open the btmp file %s: %s", _PATH_BTMP,
		    strerror(errno));
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (fstat(fd, &fst) < 0) {
		logit("%s: fstat of %s failed: %s", __func__, _PATH_BTMP,
		    strerror(errno));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((fst.st_mode & (S_IXGRP | S_IRWXO)) || fst.st_uid != 0) {
		logit("Excess permission or bad ownership on file %s",
		    _PATH_BTMP);
		ಗಚ್ಛ out;
	}

	/* Construct a logininfo and turn it into a utmp */
	memset(&li, 0, ಪರಿಮಾಣ(li));
	li.type = LTYPE_FAILED;
	li.pid = getpid();
	strlcpy(li.ಸಾಲು, "ssh:notty", ಪರಿಮಾಣ(li.ಸಾಲು));
	strlcpy(li.username, username, ಪರಿಮಾಣ(li.username));
	strlcpy(li.hostname, hostname, ಪರಿಮಾಣ(li.hostname));
	time(&t);
	li.tv_sec = t > 0 ? (unsigned long)t : 0;
	ಯದಿ (ssh_packet_connection_is_on_socket(ssh)) {
		(ಶೂನ್ಯ)getpeername(ssh_packet_get_connection_in(ssh),
		    &li.hostaddr.sa, &fromlen);
	}
	construct_utmp(&li, &ut);

	ಯದಿ (atomicio(vwrite, fd, &ut, ಪರಿಮಾಣ(ut)) != ಪರಿಮಾಣ(ut)) {
		error("Failed to write to %s: %s", _PATH_BTMP,
		    strerror(errno));
	}
out:
	close(fd);
}
#endif	/* USE_BTMP */
