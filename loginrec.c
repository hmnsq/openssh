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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_WTMPDB
# include <wtmpdb.h>
#ಆದರೆ_ಅಂತ್ಯ

/**
 ** prototypes for helper functions in this file
 **/

#ಆದರೆ HAVE_UTMP_H
ಶೂನ್ಯ ಗಣ_utmp_ಸಮಯ(ರಚನೆ logininfo *li, ರಚನೆ utmp *ut);
ಶೂನ್ಯ construct_utmp(ರಚನೆ logininfo *li, ರಚನೆ utmp *ut);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_UTMPX_H
ಶೂನ್ಯ ಗಣ_utmpx_ಸಮಯ(ರಚನೆ logininfo *li, ರಚನೆ utmpx *ut);
ಶೂನ್ಯ construct_utmpx(ರಚನೆ logininfo *li, ರಚನೆ utmpx *ut);
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ utmp_write_ನಮೂದು(ರಚನೆ logininfo *li);
ಪೂರ್ಣಾಂಕ utmpx_write_ನಮೂದು(ರಚನೆ logininfo *li);
ಪೂರ್ಣಾಂಕ wtmp_write_ನಮೂದು(ರಚನೆ logininfo *li);
ಪೂರ್ಣಾಂಕ wtmpx_write_ನಮೂದು(ರಚನೆ logininfo *li);
ಪೂರ್ಣಾಂಕ lastlog_write_ನಮೂದು(ರಚನೆ logininfo *li);
ಪೂರ್ಣಾಂಕ syslogin_write_ನಮೂದು(ರಚನೆ logininfo *li);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_WTMPDB
ಪೂರ್ಣಾಂಕ wtmpdb_write_ನಮೂದು(ರಚನೆ logininfo *li);
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ getlast_ನಮೂದು(ರಚನೆ logininfo *li);
ಪೂರ್ಣಾಂಕ lastlog_get_ನಮೂದು(ರಚನೆ logininfo *li);
ಪೂರ್ಣಾಂಕ utmpx_get_ನಮೂದು(ರಚನೆ logininfo *li);
ಪೂರ್ಣಾಂಕ wtmp_get_ನಮೂದು(ರಚನೆ logininfo *li);
ಪೂರ್ಣಾಂಕ wtmpx_get_ನಮೂದು(ರಚನೆ logininfo *li);

ಬಾಹ್ಯ ರಚನೆ sshbuf *loginmsg;

/* pick the shortest string */
#ವ್ಯಾಖ್ಯಾನಿಸು MIN_SIZEOF(s1,s2) (ಗಾತ್ರ(s1) < ಗಾತ್ರ(s2) ? ಗಾತ್ರ(s1) : ಗಾತ್ರ(s2))

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
ಪೂರ್ಣಾಂಕ
login_login(ರಚನೆ logininfo *li)
{
	li->type = LTYPE_LOGIN;
	ಹಿಂತಿರುಗಿ (login_write(li));
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
ಪೂರ್ಣಾಂಕ
login_logout(ರಚನೆ logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	ಹಿಂತಿರುಗಿ (login_write(li));
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
ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ
login_get_lastlog_ಸಮಯ(ಸ್ಥಿರಾಂಕ uid_t uid)
{
	ರಚನೆ logininfo li;

	ಆದರೆ (login_get_lastlog(&li, uid))
		ಹಿಂತಿರುಗಿ (li.tv_sec);
	ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ (0);
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
ರಚನೆ logininfo *
login_get_lastlog(ರಚನೆ logininfo *li, ಸ್ಥಿರಾಂಕ uid_t uid)
{
	ರಚನೆ passwd *pw;

	memset(li, '\0', ಗಾತ್ರ(*li));
	li->uid = uid;

	/*
	 * If we don't have a 'real' lastlog, we need the username to
	 * reliably search wtmp(x) for the last login (see
	 * wtmp_get_entry().)
	 */
	pw = getpwuid(uid);
	ಆದರೆ (pw == ಖಾಲಿ)
		fatal("%s: Cannot find account for uid %ld", __func__,
		    (ದೀರ್ಘ)uid);

	ಆದರೆ (strlcpy(li->username, pw->pw_name, ಗಾತ್ರ(li->username)) >=
	    ಗಾತ್ರ(li->username)) {
		error("%s: username too long (%lu > max %lu)", __func__,
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ)ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pw->pw_name),
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ)ಗಾತ್ರ(li->username) - 1);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	ಆದರೆ (getlast_ನಮೂದು(li))
		ಹಿಂತಿರುಗಿ (li);
	ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
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
ರಚನೆ
logininfo *login_alloc_ನಮೂದು(pid_t pid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *username,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಾಲು)
{
	ರಚನೆ logininfo *newli;

	newli = xmalloc(ಗಾತ್ರ(*newli));
	login_init_ನಮೂದು(newli, pid, username, hostname, ಸಾಲು);
	ಹಿಂತಿರುಗಿ (newli);
}


/* login_free_entry(struct logininfo *)    - free struct memory */
ಶೂನ್ಯ
login_free_ನಮೂದು(ರಚನೆ logininfo *li)
{
	ಬಿಡುಗಡೆ(li);
}


/* login_init_entry(struct logininfo *, int, char*, char*, char*)
 *                                        - initialise a struct logininfo
 *
 * Populates a new struct logininfo, a data structure meant to carry
 * the information required to portably record login info.
 *
 * Returns: 1
 */
ಪೂರ್ಣಾಂಕ
login_init_ನಮೂದು(ರಚನೆ logininfo *li, pid_t pid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *username,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಾಲು)
{
	ರಚನೆ passwd *pw;

	memset(li, 0, ಗಾತ್ರ(*li));

	li->pid = pid;

	/* set the line information */
	ಆದರೆ (ಸಾಲು)
		ಸಾಲು_fullname(li->ಸಾಲು, ಸಾಲು, ಗಾತ್ರ(li->ಸಾಲು));

	ಆದರೆ (username) {
		strlcpy(li->username, username, ಗಾತ್ರ(li->username));
		pw = getpwnam(li->username);
		ಆದರೆ (pw == ಖಾಲಿ) {
			fatal("%s: Cannot find user \"%s\"", __func__,
			    li->username);
		}
		li->uid = pw->pw_uid;
	}

	ಆದರೆ (hostname)
		strlcpy(li->hostname, hostname, ಗಾತ್ರ(li->hostname));

	ಹಿಂತಿರುಗಿ (1);
}

/*
 * login_set_current_time(struct logininfo *)    - set the current time
 *
 * Set the current time in a logininfo structure. This function is
 * meant to eliminate the need to deal with system dependencies for
 * time handling.
 */
ಶೂನ್ಯ
login_ಗಣ_current_ಸಮಯ(ರಚನೆ logininfo *li)
{
	ರಚನೆ timeval tv;

	gettimeofday(&tv, ಖಾಲಿ);

	li->tv_sec = tv.tv_sec;
	li->tv_usec = tv.tv_usec;
}

/* copy a sockaddr_* into our logininfo */
ಶೂನ್ಯ
login_ಗಣ_addr(ರಚನೆ logininfo *li, ಸ್ಥಿರಾಂಕ ರಚನೆ sockaddr *sa,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ sa_ಗಾತ್ರ)
{
	ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ bufsize = sa_ಗಾತ್ರ;

	/* make sure we don't overrun our union */
	ಆದರೆ (ಗಾತ್ರ(li->hostaddr) < sa_ಗಾತ್ರ)
		bufsize = ಗಾತ್ರ(li->hostaddr);

	ಸ್ಮರಣೆ_ನಕಲು(&li->hostaddr.sa, sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/
ಪೂರ್ಣಾಂಕ
login_write(ರಚನೆ logininfo *li)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_CYGWIN
	ಆದರೆ (geteuid() != 0) {
		logit("Attempt to write login records by non-root user (aborting)");
		ಹಿಂತಿರುಗಿ (1);
	}
#ಆದರೆ_ಅಂತ್ಯ

	/* set the timestamp */
	login_ಗಣ_current_ಸಮಯ(li);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LOGIN
	syslogin_write_ನಮೂದು(li);
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LASTLOG
	ಆದರೆ (li->type == LTYPE_LOGIN)
		lastlog_write_ನಮೂದು(li);
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_UTMP
	utmp_write_ನಮೂದು(li);
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_WTMP
	wtmp_write_ನಮೂದು(li);
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_UTMPX
	utmpx_write_ನಮೂದು(li);
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_WTMPX
	wtmpx_write_ನಮೂದು(li);
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_WTMPDB
	wtmpdb_write_ನಮೂದು(li);
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ CUSTOM_SYS_AUTH_ದಾಖಲೆ_LOGIN
	ಆದರೆ (li->type == LTYPE_LOGIN &&
	    !sys_auth_ದಾಖಲೆ_login(li->username,li->hostname,li->ಸಾಲು,
	    loginmsg))
		logit("Writing login record failed for %s", li->username);
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
	ಆದರೆ (li->type == LTYPE_LOGIN)
		audit_session_open(li);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (li->type == LTYPE_LOGOUT)
		audit_session_close(li);
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ (0);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LOGIN_NEEDS_UTMPX
ಪೂರ್ಣಾಂಕ
login_utmp_only(ರಚನೆ logininfo *li)
{
	li->type = LTYPE_LOGIN;
	login_ಗಣ_current_ಸಮಯ(li);
# ifdef USE_UTMP
	utmp_write_ನಮೂದು(li);
# endif
# ifdef USE_WTMP
	wtmp_write_ನಮೂದು(li);
# endif
# ifdef USE_UTMPX
	utmpx_write_ನಮೂದು(li);
# endif
# ifdef USE_WTMPX
	wtmpx_write_ನಮೂದು(li);
# endif
	ಹಿಂತಿರುಗಿ (0);
}
#ಆದರೆ_ಅಂತ್ಯ

/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
ಪೂರ್ಣಾಂಕ
getlast_ನಮೂದು(ರಚನೆ logininfo *li)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LASTLOG
	ಹಿಂತಿರುಗಿ(lastlog_get_ನಮೂದು(li));
#ಇಲ್ಲದಿದ್ದರೆ /* !USE_LASTLOG */
#ಆದರೆ defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
	ಹಿಂತಿರುಗಿ (utmpx_get_ನಮೂದು(li));
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(DISABLE_LASTLOG)
	/* On some systems we shouldn't even try to obtain last login
	 * time, e.g. AIX */
	ಹಿಂತಿರುಗಿ (0);
# elif defined(USE_WTMP) && \
    (defined(HAVE_ಸಮಯ_ಒಳ_UTMP) || defined(HAVE_TV_ಒಳ_UTMP))
	/* retrieve last login time from utmp */
	ಹಿಂತಿರುಗಿ (wtmp_get_ನಮೂದು(li));
# elif defined(USE_WTMPX) && \
    (defined(HAVE_ಸಮಯ_ಒಳ_UTMPX) || defined(HAVE_TV_ಒಳ_UTMPX))
	/* If wtmp isn't available, try wtmpx */
	ಹಿಂತಿರುಗಿ (wtmpx_get_ನಮೂದು(li));
# ಇಲ್ಲದಿದ್ದರೆ
	/* Give up: No means of retrieving last login time */
	ಹಿಂತಿರುಗಿ (0);
# endif /* DISABLE_LASTLOG */
#ಆದರೆ_ಅಂತ್ಯ /* USE_LASTLOG */
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
ಅಕ್ಷರ *
ಸಾಲು_fullname(ಅಕ್ಷರ *dst, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, u_int dstsize)
{
	memset(dst, '\0', dstsize);
	ಆದರೆ ((ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(src, "/dev/", 5) == 0) || (dstsize < (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(src) + 5)))
		strlcpy(dst, src, dstsize);
	ಇಲ್ಲದಿದ್ದರೆ {
		strlcpy(dst, "/dev/", dstsize);
		strlcat(dst, src, dstsize);
	}
	ಹಿಂತಿರುಗಿ (dst);
}

/* line_stripname(): strip the leading '/dev' if it exists, return dst */
ಅಕ್ಷರ *
ಸಾಲು_stripname(ಅಕ್ಷರ *dst, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಪೂರ್ಣಾಂಕ dstsize)
{
	memset(dst, '\0', dstsize);
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(src, "/dev/", 5) == 0)
		strlcpy(dst, src + 5, dstsize);
	ಇಲ್ಲದಿದ್ದರೆ
		strlcpy(dst, src, dstsize);
	ಹಿಂತಿರುಗಿ (dst);
}

/*
 * line_abbrevname(): Return the abbreviated (usually four-character)
 * form of the line (Just use the last <dstsize> characters of the
 * full name.)
 *
 * NOTE: use strncpy because we do NOT necessarily want zero
 * termination
 */
ಅಕ್ಷರ *
ಸಾಲು_abbrevname(ಅಕ್ಷರ *dst, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಪೂರ್ಣಾಂಕ dstsize)
{
	ಗಾತ್ರ_t len;

	memset(dst, '\0', dstsize);

	ಆದರೆ (strcmp(src, "ssh:notty") == 0)
		ಹಿಂತಿರುಗಿ dst;

	/* Always skip prefix if present */
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(src, "/dev/", 5) == 0)
		src += 5;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_ABBREV_NO_TTY
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(src, "tty", 3) == 0)
		src += 3;
#ಆದರೆ_ಅಂತ್ಯ

	len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(src);

	ಆದರೆ (len > 0) {
		ಆದರೆ (((ಪೂರ್ಣಾಂಕ)len - dstsize) > 0)
			src +=  ((ಪೂರ್ಣಾಂಕ)len - dstsize);

		/* note: _don't_ change this to strlcpy */
		strncpy(dst, src, (ಗಾತ್ರ_t)dstsize);
	}

	ಹಿಂತಿರುಗಿ (dst);
}

/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#ಆದರೆ defined(USE_BTMP) || defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
ಶೂನ್ಯ
ಗಣ_utmp_ಸಮಯ(ರಚನೆ logininfo *li, ರಚನೆ utmp *ut)
{
# ಆದರೆ defined(HAVE_TV_ಒಳ_UTMP)
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_ಸಮಯ_ಒಳ_UTMP)
	ut->ut_ಸಮಯ = li->tv_sec;
# endif
}

ಶೂನ್ಯ
construct_utmp(ರಚನೆ logininfo *li,
		    ರಚನೆ utmp *ut)
{
# ifdef HAVE_ADDR_V6_ಒಳ_UTMP
	ರಚನೆ sockaddr_in6 *sa6;
# endif

	memset(ut, '\0', ಗಾತ್ರ(*ut));

	/* First fill out fields used for both logins and logouts */

# ifdef HAVE_ID_ಒಳ_UTMP
	ಸಾಲು_abbrevname(ut->ut_id, li->ಸಾಲು, ಗಾತ್ರ(ut->ut_id));
# endif

# ifdef HAVE_TYPE_ಒಳ_UTMP
	/* This is done here to keep utmp constants out of struct logininfo */
	ಆಯ್ಕೆ (li->type) {
	ಸ್ಥಿತಿ LTYPE_FAILED:
		ut->ut_type = LOGIN_PROCESS;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		ನಿಲ್ಲಿಸು;
	}
# endif
	ಗಣ_utmp_ಸಮಯ(li, ut);

	ಸಾಲು_stripname(ut->ut_ಸಾಲು, li->ಸಾಲು, ಗಾತ್ರ(ut->ut_ಸಾಲು));

# ifdef HAVE_PID_ಒಳ_UTMP
	ut->ut_pid = li->pid;
# endif

	/* If we're logging out, leave all other fields blank */
	ಆದರೆ (li->type == LTYPE_LOGOUT)
		ಹಿಂತಿರುಗಿ;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

	/* Use strncpy because we don't necessarily want null termination */
	strncpy(ut->ut_name, li->username,
	    MIN_SIZEOF(ut->ut_name, li->username));
# ifdef HAVE_HOST_ಒಳ_UTMP
	strncpy(ut->ut_host, li->hostname,
	    MIN_SIZEOF(ut->ut_host, li->hostname));
# endif
# ifdef HAVE_ADDR_ಒಳ_UTMP
	/* this is just a 32-bit IP address */
	ಆದರೆ (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_ಒಳ.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_ಒಳ_UTMP
	/* this is just a 128-bit IPv6 address */
	ಆದರೆ (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((ರಚನೆ sockaddr_in6 *)&li->hostaddr.sa);
		ಸ್ಮರಣೆ_ನಕಲು(ut->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		ಆದರೆ (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			ut->ut_addr_v6[0] = ut->ut_addr_v6[3];
			ut->ut_addr_v6[1] = 0;
			ut->ut_addr_v6[2] = 0;
			ut->ut_addr_v6[3] = 0;
		}
	}
# endif
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_BTMP || USE_UTMP || USE_WTMP || USE_LOGIN */

/**
 ** utmpx utility functions
 **
 ** These functions manipulate struct utmpx, accounting for system
 ** variations.
 **/

#ಆದರೆ defined(USE_UTMPX) || defined (USE_WTMPX)
/* build the utmpx structure */
ಶೂನ್ಯ
ಗಣ_utmpx_ಸಮಯ(ರಚನೆ logininfo *li, ರಚನೆ utmpx *utx)
{
# ಆದರೆ defined(HAVE_TV_ಒಳ_UTMPX)
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_ಸಮಯ_ಒಳ_UTMPX)
	utx->ut_ಸಮಯ = li->tv_sec;
# endif
}

ಶೂನ್ಯ
construct_utmpx(ರಚನೆ logininfo *li, ರಚನೆ utmpx *utx)
{
# ifdef HAVE_ADDR_V6_ಒಳ_UTMPX
	ರಚನೆ sockaddr_in6 *sa6;
#  endif
	memset(utx, '\0', ಗಾತ್ರ(*utx));

# ifdef HAVE_ID_ಒಳ_UTMPX
	ಸಾಲು_abbrevname(utx->ut_id, li->ಸಾಲು, ಗಾತ್ರ(utx->ut_id));
# endif

	/* this is done here to keep utmp constants out of loginrec.h */
	ಆಯ್ಕೆ (li->type) {
	ಸ್ಥಿತಿ LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		ನಿಲ್ಲಿಸು;
	}
	ಸಾಲು_stripname(utx->ut_ಸಾಲು, li->ಸಾಲು, ಗಾತ್ರ(utx->ut_ಸಾಲು));
	ಗಣ_utmpx_ಸಮಯ(li, utx);
	utx->ut_pid = li->pid;

	/* strncpy(): Don't necessarily want null termination */
	strncpy(utx->ut_user, li->username,
	    MIN_SIZEOF(utx->ut_user, li->username));

	ಆದರೆ (li->type == LTYPE_LOGOUT)
		ಹಿಂತಿರುಗಿ;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

# ifdef HAVE_HOST_ಒಳ_UTMPX
	strncpy(utx->ut_host, li->hostname,
	    MIN_SIZEOF(utx->ut_host, li->hostname));
# endif
# ifdef HAVE_SS_ಒಳ_UTMPX
	utx->ut_ss = li->hostaddr.sa_storage;
# endif
# ifdef HAVE_ADDR_ಒಳ_UTMPX
	/* this is just a 32-bit IP address */
	ಆದರೆ (li->hostaddr.sa.sa_family == AF_INET)
		utx->ut_addr = li->hostaddr.sa_ಒಳ.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_ಒಳ_UTMPX
	/* this is just a 128-bit IPv6 address */
	ಆದರೆ (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((ರಚನೆ sockaddr_in6 *)&li->hostaddr.sa);
		ಸ್ಮರಣೆ_ನಕಲು(utx->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		ಆದರೆ (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			utx->ut_addr_v6[0] = utx->ut_addr_v6[3];
			utx->ut_addr_v6[1] = 0;
			utx->ut_addr_v6[2] = 0;
			utx->ut_addr_v6[3] = 0;
		}
	}
# endif
# ifdef HAVE_SYSLEN_ಒಳ_UTMPX
	/* ut_syslen is the length of the utx_host string */
	utx->ut_syslen = MINIMUM(ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(li->hostname), ಗಾತ್ರ(utx->ut_host));
# endif
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_UTMPX || USE_WTMPX */

/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_UTMP

/* if we can, use pututline() etc. */
# ಆದರೆ !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
	defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
# endif


/* write a utmp entry with the system's help (pututline() and pals) */
# ifdef UTMP_USE_LIBRARY
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
utmp_write_library(ರಚನೆ logininfo *li, ರಚನೆ utmp *ut)
{
	setutent();
	pututline(ut);
#  ifdef HAVE_ENDUTENT
	endutent();
#  endif
	ಹಿಂತಿರುಗಿ (1);
}
# ಇಲ್ಲದಿದ್ದರೆ /* UTMP_USE_LIBRARY */

/*
 * Write a utmp entry direct to the file
 * This is a slightly modification of code in OpenBSD's login.c
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
utmp_write_ನೇರ(ರಚನೆ logininfo *li, ರಚನೆ utmp *ut)
{
	ರಚನೆ utmp old_ut;
	ನೋಂದಣಿ ಪೂರ್ಣಾಂಕ fd;
	ಪೂರ್ಣಾಂಕ tty;

	/* FIXME: (ATL) ttyslot() needs local implementation */

#ಆದರೆ defined(HAVE_GETTTYENT)
	ರಚನೆ ttyent *ty;

	tty=0;
	setttyent();
	ಆಗ (ಖಾಲಿ != (ty = getttyent())) {
		tty++;
		ಆದರೆ (!ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(ty->ty_name, ut->ut_ಸಾಲು, ಗಾತ್ರ(ut->ut_ಸಾಲು)))
			ನಿಲ್ಲಿಸು;
	}
	endttyent();

	ಆದರೆ (ಖಾಲಿ == ty) {
		logit_f("tty not found");
		ಹಿಂತಿರುಗಿ (0);
	}
#ಇಲ್ಲದಿದ್ದರೆ /* FIXME */

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_GETTTYENT */

	ಆದರೆ (tty > 0 && (fd = open(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		off_t pos, ret;

		pos = (off_t)tty * ಗಾತ್ರ(ರಚನೆ utmp);
		ಆದರೆ ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			ಹಿಂತಿರುಗಿ (0);
		}
		ಆದರೆ (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			ಹಿಂತಿರುಗಿ (0);
		}
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		ಆದರೆ (atomicio(ಪಠ, fd, &old_ut, ಗಾತ್ರ(old_ut)) == ಗಾತ್ರ(old_ut) &&
		    (ut->ut_host[0] == '\0') && (old_ut.ut_host[0] != '\0') &&
		    (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(old_ut.ut_ಸಾಲು, ut->ut_ಸಾಲು, ಗಾತ್ರ(ut->ut_ಸಾಲು)) == 0) &&
		    (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(old_ut.ut_name, ut->ut_name, ಗಾತ್ರ(ut->ut_name)) == 0))
			ಸ್ಮರಣೆ_ನಕಲು(ut->ut_host, old_ut.ut_host, ಗಾತ್ರ(ut->ut_host));

		ಆದರೆ ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			ಹಿಂತಿರುಗಿ (0);
		}
		ಆದರೆ (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			ಹಿಂತಿರುಗಿ (0);
		}
		ಆದರೆ (atomicio(vwrite, fd, ut, ಗಾತ್ರ(*ut)) != ಗಾತ್ರ(*ut)) {
			logit("%s: error writing %s: %s", __func__,
			    UTMP_FILE, strerror(errno));
			close(fd);
			ಹಿಂತಿರುಗಿ (0);
		}

		close(fd);
		ಹಿಂತಿರುಗಿ (1);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಹಿಂತಿರುಗಿ (0);
	}
}
# endif /* UTMP_USE_LIBRARY */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
utmp_perform_login(ರಚನೆ logininfo *li)
{
	ರಚನೆ utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	ಆದರೆ (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		ಹಿಂತಿರುಗಿ (0);
	}
# ಇಲ್ಲದಿದ್ದರೆ
	ಆದರೆ (!utmp_write_ನೇರ(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		ಹಿಂತಿರುಗಿ (0);
	}
# endif
	ಹಿಂತಿರುಗಿ (1);
}


ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
utmp_perform_logout(ರಚನೆ logininfo *li)
{
	ರಚನೆ utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	ಆದರೆ (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		ಹಿಂತಿರುಗಿ (0);
	}
# ಇಲ್ಲದಿದ್ದರೆ
	ಆದರೆ (!utmp_write_ನೇರ(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		ಹಿಂತಿರುಗಿ (0);
	}
# endif
	ಹಿಂತಿರುಗಿ (1);
}


ಪೂರ್ಣಾಂಕ
utmp_write_ನಮೂದು(ರಚನೆ logininfo *li)
{
	ಆಯ್ಕೆ(li->type) {
	ಸ್ಥಿತಿ LTYPE_LOGIN:
		ಹಿಂತಿರುಗಿ (utmp_perform_login(li));

	ಸ್ಥಿತಿ LTYPE_LOGOUT:
		ಹಿಂತಿರುಗಿ (utmp_perform_logout(li));

	ಪೂರ್ವನಿಯೋಜಿತ:
		logit_f("invalid type field");
		ಹಿಂತಿರುಗಿ (0);
	}
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_UTMPX

/* if we have the wherewithal, use pututxline etc. */
# ಆದರೆ !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) && \
	defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
# endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
# ifdef UTMPX_USE_LIBRARY
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
utmpx_write_library(ರಚನೆ logininfo *li, ರಚನೆ utmpx *utx)
{
	setutxent();
	pututxline(utx);

#  ifdef HAVE_ENDUTXENT
	endutxent();
#  endif
	ಹಿಂತಿರುಗಿ (1);
}

# ಇಲ್ಲದಿದ್ದರೆ /* UTMPX_USE_LIBRARY */

/* write a utmp entry direct to the file */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
utmpx_write_ನೇರ(ರಚನೆ logininfo *li, ರಚನೆ utmpx *utx)
{
	logit_f("not implemented!");
	ಹಿಂತಿರುಗಿ (0);
}
# endif /* UTMPX_USE_LIBRARY */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
utmpx_perform_login(ರಚನೆ logininfo *li)
{
	ರಚನೆ utmpx utx;

	construct_utmpx(li, &utx);
# ifdef UTMPX_USE_LIBRARY
	ಆದರೆ (!utmpx_write_library(li, &utx)) {
		logit_f("utmp_write_library() failed");
		ಹಿಂತಿರುಗಿ (0);
	}
# ಇಲ್ಲದಿದ್ದರೆ
	ಆದರೆ (!utmpx_write_ನೇರ(li, &utx)) {
		logit_f("utmp_write_direct() failed");
		ಹಿಂತಿರುಗಿ (0);
	}
# endif
	ಹಿಂತಿರುಗಿ (1);
}


ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
utmpx_perform_logout(ರಚನೆ logininfo *li)
{
	ರಚನೆ utmpx utx;

	construct_utmpx(li, &utx);
# ifdef HAVE_ID_ಒಳ_UTMPX
	ಸಾಲು_abbrevname(utx.ut_id, li->ಸಾಲು, ಗಾತ್ರ(utx.ut_id));
# endif
# ifdef HAVE_TYPE_ಒಳ_UTMPX
	utx.ut_type = DEAD_PROCESS;
# endif

# ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
# ಇಲ್ಲದಿದ್ದರೆ
	utmpx_write_ನೇರ(li, &utx);
# endif
	ಹಿಂತಿರುಗಿ (1);
}

ಪೂರ್ಣಾಂಕ
utmpx_write_ನಮೂದು(ರಚನೆ logininfo *li)
{
	ಆಯ್ಕೆ(li->type) {
	ಸ್ಥಿತಿ LTYPE_LOGIN:
		ಹಿಂತಿರುಗಿ (utmpx_perform_login(li));
	ಸ್ಥಿತಿ LTYPE_LOGOUT:
		ಹಿಂತಿರುಗಿ (utmpx_perform_logout(li));
	ಪೂರ್ವನಿಯೋಜಿತ:
		logit_f("invalid type field");
		ಹಿಂತಿರುಗಿ (0);
	}
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_UTMPX */


/**
 ** Low-level wtmp functions
 **/

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_WTMP

/*
 * Write a wtmp entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
wtmp_write(ರಚನೆ logininfo *li, ರಚನೆ utmp *ut)
{
	ರಚನೆ stat buf;
	ಪೂರ್ಣಾಂಕ fd, ret = 1;

	ಆದರೆ ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem writing %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		ಹಿಂತಿರುಗಿ (0);
	}
	ಆದರೆ (fstat(fd, &buf) == 0)
		ಆದರೆ (atomicio(vwrite, fd, ut, ಗಾತ್ರ(*ut)) != ಗಾತ್ರ(*ut)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMP_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);
	ಹಿಂತಿರುಗಿ (ret);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
wtmp_perform_login(ರಚನೆ logininfo *li)
{
	ರಚನೆ utmp ut;

	construct_utmp(li, &ut);
	ಹಿಂತಿರುಗಿ (wtmp_write(li, &ut));
}


ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
wtmp_perform_logout(ರಚನೆ logininfo *li)
{
	ರಚನೆ utmp ut;

	construct_utmp(li, &ut);
	ಹಿಂತಿರುಗಿ (wtmp_write(li, &ut));
}


ಪೂರ್ಣಾಂಕ
wtmp_write_ನಮೂದು(ರಚನೆ logininfo *li)
{
	ಆಯ್ಕೆ(li->type) {
	ಸ್ಥಿತಿ LTYPE_LOGIN:
		ಹಿಂತಿರುಗಿ (wtmp_perform_login(li));
	ಸ್ಥಿತಿ LTYPE_LOGOUT:
		ಹಿಂತಿರುಗಿ (wtmp_perform_logout(li));
	ಪೂರ್ವನಿಯೋಜಿತ:
		logit_f("invalid type field");
		ಹಿಂತಿರುಗಿ (0);
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
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
wtmp_islogin(ರಚನೆ logininfo *li, ರಚನೆ utmp *ut)
{
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(li->username, ut->ut_name,
	    MIN_SIZEOF(li->username, ut->ut_name)) == 0) {
# ifdef HAVE_TYPE_ಒಳ_UTMP
		ಆದರೆ (ut->ut_type & USER_PROCESS)
			ಹಿಂತಿರುಗಿ (1);
# ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ (1);
# endif
	}
	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
wtmp_get_ನಮೂದು(ರಚನೆ logininfo *li)
{
	ರಚನೆ stat st;
	ರಚನೆ utmp ut;
	ಪೂರ್ಣಾಂಕ fd, ಸಿಕ್ಕಿತು = 0;

	/* Clear the time entries in our logininfo */
	li->tv_sec = li->tv_usec = 0;

	ಆದರೆ ((fd = open(WTMP_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		ಹಿಂತಿರುಗಿ (0);
	}
	ಆದರೆ (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		close(fd);
		ಹಿಂತಿರುಗಿ (0);
	}

	/* Seek to the start of the last struct utmp */
	ಆದರೆ (lseek(fd, -(off_t)ಗಾತ್ರ(ರಚನೆ utmp), SEEK_END) == -1) {
		/* Looks like we've got a fresh wtmp file */
		close(fd);
		ಹಿಂತಿರುಗಿ (0);
	}

	ಆಗ (!ಸಿಕ್ಕಿತು) {
		ಆದರೆ (atomicio(ಪಠ, fd, &ut, ಗಾತ್ರ(ut)) != ಗಾತ್ರ(ut)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMP_FILE, strerror(errno));
			close (fd);
			ಹಿಂತಿರುಗಿ (0);
		}
		ಆದರೆ (wtmp_islogin(li, &ut) ) {
			ಸಿಕ್ಕಿತು = 1;
			/*
			 * We've already checked for a time in struct
			 * utmp, in login_getlast()
			 */
# ifdef HAVE_ಸಮಯ_ಒಳ_UTMP
			li->tv_sec = ut.ut_ಸಮಯ;
# ಇಲ್ಲದಿದ್ದರೆ
#  ಆದರೆ HAVE_TV_ಒಳ_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
# endif
			ಸಾಲು_fullname(li->ಸಾಲು, ut.ut_ಸಾಲು,
			    MIN_SIZEOF(li->ಸಾಲು, ut.ut_ಸಾಲು));
# ifdef HAVE_HOST_ಒಳ_UTMP
			strlcpy(li->hostname, ut.ut_host,
			    MIN_SIZEOF(li->hostname, ut.ut_host));
# endif
			ಮುಂದುವರಿ;
		}
		/* Seek back 2 x struct utmp */
		ಆದರೆ (lseek(fd, -(off_t)(2 * ಗಾತ್ರ(ರಚನೆ utmp)), SEEK_CUR) == -1) {
			/* We've found the start of the file, so quit */
			close(fd);
			ಹಿಂತಿರುಗಿ (0);
		}
	}

	/* We found an entry. Tidy up and return */
	close(fd);
	ಹಿಂತಿರುಗಿ (1);
}
# endif /* USE_WTMP */


/**
 ** Low-level wtmpx functions
 **/

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_WTMPX
/*
 * Write a wtmpx entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
wtmpx_write(ರಚನೆ logininfo *li, ರಚನೆ utmpx *utx)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_UPDWTMPX
	ರಚನೆ stat buf;
	ಪೂರ್ಣಾಂಕ fd, ret = 1;

	ಆದರೆ ((fd = open(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		ಹಿಂತಿರುಗಿ (0);
	}

	ಆದರೆ (fstat(fd, &buf) == 0)
		ಆದರೆ (atomicio(vwrite, fd, utx, ಗಾತ್ರ(*utx)) != ಗಾತ್ರ(*utx)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);

	ಹಿಂತಿರುಗಿ (ret);
#ಇಲ್ಲದಿದ್ದರೆ
	updwtmpx(WTMPX_FILE, utx);
	ಹಿಂತಿರುಗಿ (1);
#ಆದರೆ_ಅಂತ್ಯ
}


ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
wtmpx_perform_login(ರಚನೆ logininfo *li)
{
	ರಚನೆ utmpx utx;

	construct_utmpx(li, &utx);
	ಹಿಂತಿರುಗಿ (wtmpx_write(li, &utx));
}


ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
wtmpx_perform_logout(ರಚನೆ logininfo *li)
{
	ರಚನೆ utmpx utx;

	construct_utmpx(li, &utx);
	ಹಿಂತಿರುಗಿ (wtmpx_write(li, &utx));
}


ಪೂರ್ಣಾಂಕ
wtmpx_write_ನಮೂದು(ರಚನೆ logininfo *li)
{
	ಆಯ್ಕೆ(li->type) {
	ಸ್ಥಿತಿ LTYPE_LOGIN:
		ಹಿಂತಿರುಗಿ (wtmpx_perform_login(li));
	ಸ್ಥಿತಿ LTYPE_LOGOUT:
		ಹಿಂತಿರುಗಿ (wtmpx_perform_logout(li));
	ಪೂರ್ವನಿಯೋಜಿತ:
		logit_f("invalid type field");
		ಹಿಂತಿರುಗಿ (0);
	}
}

/* Please see the notes above wtmp_islogin() for information about the
   next two functions */

/* Return true if this wtmpx entry indicates a login */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
wtmpx_islogin(ರಚನೆ logininfo *li, ರಚನೆ utmpx *utx)
{
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(li->username, utx->ut_user,
	    MIN_SIZEOF(li->username, utx->ut_user)) == 0 ) {
# ifdef HAVE_TYPE_ಒಳ_UTMPX
		ಆದರೆ (utx->ut_type == USER_PROCESS)
			ಹಿಂತಿರುಗಿ (1);
# ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ (1);
# endif
	}
	ಹಿಂತಿರುಗಿ (0);
}


ಪೂರ್ಣಾಂಕ
wtmpx_get_ನಮೂದು(ರಚನೆ logininfo *li)
{
	ರಚನೆ stat st;
	ರಚನೆ utmpx utx;
	ಪೂರ್ಣಾಂಕ fd, ಸಿಕ್ಕಿತು=0;

	/* Clear the time entries */
	li->tv_sec = li->tv_usec = 0;

	ಆದರೆ ((fd = open(WTMPX_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		ಹಿಂತಿರುಗಿ (0);
	}
	ಆದರೆ (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		close(fd);
		ಹಿಂತಿರುಗಿ (0);
	}

	/* Seek to the start of the last struct utmpx */
	ಆದರೆ (lseek(fd, -(off_t)ಗಾತ್ರ(ರಚನೆ utmpx), SEEK_END) == -1 ) {
		/* probably a newly rotated wtmpx file */
		close(fd);
		ಹಿಂತಿರುಗಿ (0);
	}

	ಆಗ (!ಸಿಕ್ಕಿತು) {
		ಆದರೆ (atomicio(ಪಠ, fd, &utx, ಗಾತ್ರ(utx)) != ಗಾತ್ರ(utx)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			close (fd);
			ಹಿಂತಿರುಗಿ (0);
		}
		/*
		 * Logouts are recorded as a blank username on a particular
		 * line. So, we just need to find the username in struct utmpx
		 */
		ಆದರೆ (wtmpx_islogin(li, &utx)) {
			ಸಿಕ್ಕಿತು = 1;
# ಆದರೆ defined(HAVE_TV_ಒಳ_UTMPX)
			li->tv_sec = utx.ut_tv.tv_sec;
# elif defined(HAVE_ಸಮಯ_ಒಳ_UTMPX)
			li->tv_sec = utx.ut_ಸಮಯ;
# endif
			ಸಾಲು_fullname(li->ಸಾಲು, utx.ut_ಸಾಲು, ಗಾತ್ರ(li->ಸಾಲು));
# ಆದರೆ defined(HAVE_HOST_ಒಳ_UTMPX)
			strlcpy(li->hostname, utx.ut_host,
			    MIN_SIZEOF(li->hostname, utx.ut_host));
# endif
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (lseek(fd, -(off_t)(2 * ಗಾತ್ರ(ರಚನೆ utmpx)), SEEK_CUR) == -1) {
			close(fd);
			ಹಿಂತಿರುಗಿ (0);
		}
	}

	close(fd);
	ಹಿಂತಿರುಗಿ (1);
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_WTMPX */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_WTMPDB
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
wtmpdb_perform_login(ರಚನೆ logininfo *li)
{
	uint64_t login_ಸಮಯ = li->tv_sec * ((uint64_t) 1000000ULL) +
	    li->tv_usec;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *tty;

	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(li->ಸಾಲು, "/dev/", 5) == 0)
		tty = &(li->ಸಾಲು[5]);
	ಇಲ್ಲದಿದ್ದರೆ
		tty = li->ಸಾಲು;

	li->wtmpdb_id = wtmpdb_login(ಖಾಲಿ, USER_PROCESS, li->username,
	    login_ಸಮಯ, tty, li->hostname, 0, 0);

	ಆದರೆ (li->wtmpdb_id < 0)
		ಹಿಂತಿರುಗಿ (0);

	ಹಿಂತಿರುಗಿ (1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
wtmpdb_perform_logout(ರಚನೆ logininfo *li)
{
	uint64_t logout_ಸಮಯ = li->tv_sec * ((uint64_t) 1000000ULL) +
	   li->tv_usec;

	ಆದರೆ (li->wtmpdb_id == 0) {
		ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *tty;

		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(li->ಸಾಲು, "/dev/", 5) == 0)
			tty = &(li->ಸಾಲು[5]);
		ಇಲ್ಲದಿದ್ದರೆ
			tty = li->ಸಾಲು;

		li->wtmpdb_id = wtmpdb_get_id(ಖಾಲಿ, tty, ಖಾಲಿ);
	}
	wtmpdb_logout(ಖಾಲಿ, li->wtmpdb_id, logout_ಸಮಯ, ಖಾಲಿ);

	ಹಿಂತಿರುಗಿ (1);
}

ಪೂರ್ಣಾಂಕ
wtmpdb_write_ನಮೂದು(ರಚನೆ logininfo *li)
{
	ಆಯ್ಕೆ(li->type) {
	ಸ್ಥಿತಿ LTYPE_LOGIN:
		ಹಿಂತಿರುಗಿ (wtmpdb_perform_login(li));
	ಸ್ಥಿತಿ LTYPE_LOGOUT:
		ಹಿಂತಿರುಗಿ (wtmpdb_perform_logout(li));
	ಪೂರ್ವನಿಯೋಜಿತ:
		logit_f("invalid type field");
		ಹಿಂತಿರುಗಿ (0);
	}
}
#ಆದರೆ_ಅಂತ್ಯ

/**
 ** Low-level libutil login() functions
 **/

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LOGIN
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
syslogin_perform_login(ರಚನೆ logininfo *li)
{
	ರಚನೆ utmp *ut;

	ut = xmalloc(ಗಾತ್ರ(*ut));
	construct_utmp(li, ut);
	login(ut);
	ಬಿಡುಗಡೆ(ut);

	ಹಿಂತಿರುಗಿ (1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
syslogin_perform_logout(ರಚನೆ logininfo *li)
{
# ifdef HAVE_LOGOUT
	ಅಕ್ಷರ ಸಾಲು[UT_LINESIZE];

	(ಶೂನ್ಯ)ಸಾಲು_stripname(ಸಾಲು, li->ಸಾಲು, ಗಾತ್ರ(ಸಾಲು));

	ಆದರೆ (!logout(ಸಾಲು))
		logit_f("logout() returned an error");
#  ifdef HAVE_LOGWTMP
	ಇಲ್ಲದಿದ್ದರೆ
		logwtmp(ಸಾಲು, "", "");
#  endif
	/* FIXME: (ATL - if the need arises) What to do if we have
	 * login, but no logout?  what if logout but no logwtmp? All
	 * routines are in libutil so they should all be there,
	 * but... */
# endif
	ಹಿಂತಿರುಗಿ (1);
}

ಪೂರ್ಣಾಂಕ
syslogin_write_ನಮೂದು(ರಚನೆ logininfo *li)
{
	ಆಯ್ಕೆ (li->type) {
	ಸ್ಥಿತಿ LTYPE_LOGIN:
		ಹಿಂತಿರುಗಿ (syslogin_perform_login(li));
	ಸ್ಥಿತಿ LTYPE_LOGOUT:
		ಹಿಂತಿರುಗಿ (syslogin_perform_logout(li));
	ಪೂರ್ವನಿಯೋಜಿತ:
		logit_f("Invalid type field");
		ಹಿಂತಿರುಗಿ (0);
	}
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_LOGIN */

/* end of file log-syslogin.c */

/**
 ** Low-level lastlog functions
 **/

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LASTLOG

#ಆದರೆ !defined(LASTLOG_WRITE_PUTUTXLINE) || !defined(HAVE_GETLASTLOGXBYNAME)
/* open the file (using filemode) and seek to the login entry */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
lastlog_openseek(ರಚನೆ logininfo *li, ಪೂರ್ಣಾಂಕ *fd, ಪೂರ್ಣಾಂಕ filemode)
{
	off_t ಸ್ಥಾನಾಂತರ;
	ಅಕ್ಷರ lastlog_file[1024];
	ರಚನೆ stat st;

	ಆದರೆ (stat(LASTLOG_FILE, &st) != 0) {
		logit("%s: Couldn't stat %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		ಹಿಂತಿರುಗಿ (0);
	}
	ಆದರೆ (S_ISDIR(st.st_mode)) {
		snprintf(lastlog_file, ಗಾತ್ರ(lastlog_file), "%s/%s",
		    LASTLOG_FILE, li->username);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (S_ISREG(st.st_mode)) {
		strlcpy(lastlog_file, LASTLOG_FILE, ಗಾತ್ರ(lastlog_file));
	} ಇಲ್ಲದಿದ್ದರೆ {
		logit("%s: %.100s is not a file or directory!", __func__,
		    LASTLOG_FILE);
		ಹಿಂತಿರುಗಿ (0);
	}

	*fd = open(lastlog_file, filemode, 0600);
	ಆದರೆ (*fd < 0) {
		debug("%s: Couldn't open %s: %s", __func__,
		    lastlog_file, strerror(errno));
		ಹಿಂತಿರುಗಿ (0);
	}

	ಆದರೆ (S_ISREG(st.st_mode)) {
		/* find this uid's offset in the lastlog file */
		ಸ್ಥಾನಾಂತರ = (off_t) ((u_long)li->uid * ಗಾತ್ರ(ರಚನೆ lastlog));

		ಆದರೆ (lseek(*fd, ಸ್ಥಾನಾಂತರ, SEEK_SET) != ಸ್ಥಾನಾಂತರ) {
			logit("%s: %s->lseek(): %s", __func__,
			    lastlog_file, strerror(errno));
			close(*fd);
			ಹಿಂತಿರುಗಿ (0);
		}
	}

	ಹಿಂತಿರುಗಿ (1);
}
#ಆದರೆ_ಅಂತ್ಯ /* !LASTLOG_WRITE_PUTUTXLINE || !HAVE_GETLASTLOGXBYNAME */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LASTLOG_WRITE_PUTUTXLINE
ಪೂರ್ಣಾಂಕ
lastlog_write_ನಮೂದು(ರಚನೆ logininfo *li)
{
	ಆಯ್ಕೆ(li->type) {
	ಸ್ಥಿತಿ LTYPE_LOGIN:
		ಹಿಂತಿರುಗಿ 1; /* lastlog written by pututxline */
	ಪೂರ್ವನಿಯೋಜಿತ:
		logit("lastlog_write_entry: Invalid type field");
		ಹಿಂತಿರುಗಿ 0;
	}
}
#ಇಲ್ಲದಿದ್ದರೆ /* LASTLOG_WRITE_PUTUTXLINE */
ಪೂರ್ಣಾಂಕ
lastlog_write_ನಮೂದು(ರಚನೆ logininfo *li)
{
	ರಚನೆ lastlog ಕೊನೆಯ;
	ಪೂರ್ಣಾಂಕ fd;

	ಆಯ್ಕೆ(li->type) {
	ಸ್ಥಿತಿ LTYPE_LOGIN:
		/* create our struct lastlog */
		memset(&ಕೊನೆಯ, '\0', ಗಾತ್ರ(ಕೊನೆಯ));
		ಸಾಲು_stripname(ಕೊನೆಯ.ll_ಸಾಲು, li->ಸಾಲು, ಗಾತ್ರ(ಕೊನೆಯ.ll_ಸಾಲು));
		strlcpy(ಕೊನೆಯ.ll_host, li->hostname,
		    MIN_SIZEOF(ಕೊನೆಯ.ll_host, li->hostname));
		ಕೊನೆಯ.ll_ಸಮಯ = li->tv_sec;

		ಆದರೆ (!lastlog_openseek(li, &fd, O_RDWR|O_CREAT))
			ಹಿಂತಿರುಗಿ (0);

		/* write the entry */
		ಆದರೆ (atomicio(vwrite, fd, &ಕೊನೆಯ, ಗಾತ್ರ(ಕೊನೆಯ)) != ಗಾತ್ರ(ಕೊನೆಯ)) {
			close(fd);
			logit("%s: Error writing to %s: %s", __func__,
			    LASTLOG_FILE, strerror(errno));
			ಹಿಂತಿರುಗಿ (0);
		}

		close(fd);
		ಹಿಂತಿರುಗಿ (1);
	ಪೂರ್ವನಿಯೋಜಿತ:
		logit_f("Invalid type field");
		ಹಿಂತಿರುಗಿ (0);
	}
}
#ಆದರೆ_ಅಂತ್ಯ /* LASTLOG_WRITE_PUTUTXLINE */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_GETLASTLOGXBYNAME
ಪೂರ್ಣಾಂಕ
lastlog_get_ನಮೂದು(ರಚನೆ logininfo *li)
{
	ರಚನೆ lastlogx l, *ll;

	ಆದರೆ ((ll = getlastlogxbyname(li->username, &l)) == ಖಾಲಿ) {
		memset(&l, '\0', ಗಾತ್ರ(l));
		ll = &l;
	}
	ಸಾಲು_fullname(li->ಸಾಲು, ll->ll_ಸಾಲು, ಗಾತ್ರ(li->ಸಾಲು));
	strlcpy(li->hostname, ll->ll_host,
		MIN_SIZEOF(li->hostname, ll->ll_host));
	li->tv_sec = ll->ll_tv.tv_sec;
	li->tv_usec = ll->ll_tv.tv_usec;
	ಹಿಂತಿರುಗಿ (1);
}
#ಇಲ್ಲದಿದ್ದರೆ /* HAVE_GETLASTLOGXBYNAME */
ಪೂರ್ಣಾಂಕ
lastlog_get_ನಮೂದು(ರಚನೆ logininfo *li)
{
	ರಚನೆ lastlog ಕೊನೆಯ;
	ಪೂರ್ಣಾಂಕ fd, ret;

	ಆದರೆ (!lastlog_openseek(li, &fd, O_RDONLY))
		ಹಿಂತಿರುಗಿ (0);

	ret = atomicio(ಪಠ, fd, &ಕೊನೆಯ, ಗಾತ್ರ(ಕೊನೆಯ));
	close(fd);

	ಆಯ್ಕೆ (ret) {
	ಸ್ಥಿತಿ 0:
		memset(&ಕೊನೆಯ, '\0', ಗಾತ್ರ(ಕೊನೆಯ));
		/* FALLTHRU */
	ಸ್ಥಿತಿ ಗಾತ್ರ(ಕೊನೆಯ):
		ಸಾಲು_fullname(li->ಸಾಲು, ಕೊನೆಯ.ll_ಸಾಲು, ಗಾತ್ರ(li->ಸಾಲು));
		strlcpy(li->hostname, ಕೊನೆಯ.ll_host,
		    MIN_SIZEOF(li->hostname, ಕೊನೆಯ.ll_host));
		li->tv_sec = ಕೊನೆಯ.ll_ಸಮಯ;
		ಹಿಂತಿರುಗಿ (1);
	ಸ್ಥಿತಿ -1:
		error("%s: Error reading from %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		ಹಿಂತಿರುಗಿ (0);
	ಪೂರ್ವನಿಯೋಜಿತ:
		error("%s: Error reading from %s: Expecting %d, got %d",
		    __func__, LASTLOG_FILE, (ಪೂರ್ಣಾಂಕ)ಗಾತ್ರ(ಕೊನೆಯ), ret);
		ಹಿಂತಿರುಗಿ (0);
	}

	/* NOTREACHED */
	ಹಿಂತಿರುಗಿ (0);
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_GETLASTLOGXBYNAME */
#ಆದರೆ_ಅಂತ್ಯ /* USE_LASTLOG */

#ಆದರೆ defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
ಪೂರ್ಣಾಂಕ
utmpx_get_ನಮೂದು(ರಚನೆ logininfo *li)
{
	ರಚನೆ utmpx *utx;

	ಆದರೆ (setutxdb(UTXDB_LASTLOGIN, ಖಾಲಿ) != 0)
		ಹಿಂತಿರುಗಿ (0);
	utx = getutxuser(li->username);
	ಆದರೆ (utx == ಖಾಲಿ) {
		endutxent();
		ಹಿಂತಿರುಗಿ (0);
	}

	ಸಾಲು_fullname(li->ಸಾಲು, utx->ut_ಸಾಲು,
	    MIN_SIZEOF(li->ಸಾಲು, utx->ut_ಸಾಲು));
	strlcpy(li->hostname, utx->ut_host,
	    MIN_SIZEOF(li->hostname, utx->ut_host));
	li->tv_sec = utx->ut_tv.tv_sec;
	li->tv_usec = utx->ut_tv.tv_usec;
	endutxent();
	ಹಿಂತಿರುಗಿ (1);
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_UTMPX && HAVE_SETUTXDB && UTXDB_LASTLOGIN && HAVE_GETUTXUSER */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_BTMP
/*
 * Logs failed login attempts in _PATH_BTMP if that exists.
 * The most common login failure is to give password instead of username.
 * So the _PATH_BTMP file is checked for the correct permission, so that only
 * root can read it.
 */
ಶೂನ್ಯ
ದಾಖಲೆ_failed_login(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *username, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ttyn)
{
	ಪೂರ್ಣಾಂಕ fd;
	ರಚನೆ utmp ut;
	ರಚನೆ logininfo li;
	socklen_t fromlen = ಗಾತ್ರ(li.hostaddr);
	time_t t;
	ರಚನೆ stat fst;

	ಆದರೆ (geteuid() != 0)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ ((fd = open(ಮಾರ್ಗ_BTMP, O_WRONLY | O_APPEND)) < 0) {
		debug("Unable to open the btmp file %s: %s", ಮಾರ್ಗ_BTMP,
		    strerror(errno));
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (fstat(fd, &fst) < 0) {
		logit("%s: fstat of %s failed: %s", __func__, ಮಾರ್ಗ_BTMP,
		    strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((fst.st_mode & (S_IXGRP | S_IRWXO)) || fst.st_uid != 0) {
		logit("Excess permission or bad ownership on file %s",
		    ಮಾರ್ಗ_BTMP);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Construct a logininfo and turn it into a utmp */
	memset(&li, 0, ಗಾತ್ರ(li));
	li.type = LTYPE_FAILED;
	li.pid = getpid();
	strlcpy(li.ಸಾಲು, "ssh:notty", ಗಾತ್ರ(li.ಸಾಲು));
	strlcpy(li.username, username, ಗಾತ್ರ(li.username));
	strlcpy(li.hostname, hostname, ಗಾತ್ರ(li.hostname));
	time(&t);
	li.tv_sec = t > 0 ? (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ)t : 0;
	ಆದರೆ (ssh_packet_connection_is_on_socket(ssh)) {
		(ಶೂನ್ಯ)getpeername(ssh_packet_get_connection_ಒಳ(ssh),
		    &li.hostaddr.sa, &fromlen);
	}
	construct_utmp(&li, &ut);

	ಆದರೆ (atomicio(vwrite, fd, &ut, ಗಾತ್ರ(ut)) != ಗಾತ್ರ(ut)) {
		error("Failed to write to %s: %s", ಮಾರ್ಗ_BTMP,
		    strerror(errno));
	}
ಹೊರಹೋಗು:
	close(fd);
}
#ಆದರೆ_ಅಂತ್ಯ	/* USE_BTMP */
