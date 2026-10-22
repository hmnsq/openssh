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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "loginrec.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

# include <util.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_WTMPDB
# include <wtmpdb.h>
#ਜੇ_ਅੰਤ

/**
 ** prototypes for helper functions in this file
 **/

#ਜੇ HAVE_UTMP_H
ਖਾਲੀ ਸੈੱਟ_utmp_ਸਮਾਂ(ਬਣਤਰ logininfo *li, ਬਣਤਰ utmp *ut);
ਖਾਲੀ construct_utmp(ਬਣਤਰ logininfo *li, ਬਣਤਰ utmp *ut);
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_UTMPX_H
ਖਾਲੀ ਸੈੱਟ_utmpx_ਸਮਾਂ(ਬਣਤਰ logininfo *li, ਬਣਤਰ utmpx *ut);
ਖਾਲੀ construct_utmpx(ਬਣਤਰ logininfo *li, ਬਣਤਰ utmpx *ut);
#ਜੇ_ਅੰਤ

ਪੂਰਨ utmp_write_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li);
ਪੂਰਨ utmpx_write_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li);
ਪੂਰਨ wtmp_write_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li);
ਪੂਰਨ wtmpx_write_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li);
ਪੂਰਨ lastlog_write_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li);
ਪੂਰਨ syslogin_write_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_WTMPDB
ਪੂਰਨ wtmpdb_write_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li);
#ਜੇ_ਅੰਤ

ਪੂਰਨ getlast_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li);
ਪੂਰਨ lastlog_get_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li);
ਪੂਰਨ utmpx_get_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li);
ਪੂਰਨ wtmp_get_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li);
ਪੂਰਨ wtmpx_get_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li);

ਬਾਹਰੀ ਬਣਤਰ sshbuf *loginmsg;

/* pick the shortest string */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MIN_SIZEOF(s1,s2) (ਆਕਾਰ(s1) < ਆਕਾਰ(s2) ? ਆਕਾਰ(s1) : ਆਕਾਰ(s2))

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
ਪੂਰਨ
login_login(ਬਣਤਰ logininfo *li)
{
	li->type = LTYPE_LOGIN;
	ਵਾਪਸ (login_write(li));
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
ਪੂਰਨ
login_logout(ਬਣਤਰ logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	ਵਾਪਸ (login_write(li));
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
ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ
login_get_lastlog_ਸਮਾਂ(ਅਚਲ uid_t uid)
{
	ਬਣਤਰ logininfo li;

	ਜੇ (login_get_lastlog(&li, uid))
		ਵਾਪਸ (li.tv_sec);
	ਨਹੀਂਤਾਂ
		ਵਾਪਸ (0);
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
ਬਣਤਰ logininfo *
login_get_lastlog(ਬਣਤਰ logininfo *li, ਅਚਲ uid_t uid)
{
	ਬਣਤਰ passwd *pw;

	memset(li, '\0', ਆਕਾਰ(*li));
	li->uid = uid;

	/*
	 * If we don't have a 'real' lastlog, we need the username to
	 * reliably search wtmp(x) for the last login (see
	 * wtmp_get_entry().)
	 */
	pw = getpwuid(uid);
	ਜੇ (pw == ਨਿਰਾ)
		fatal("%s: Cannot find account for uid %ld", __func__,
		    (ਲੰਮਾ)uid);

	ਜੇ (strlcpy(li->username, pw->pw_name, ਆਕਾਰ(li->username)) >=
	    ਆਕਾਰ(li->username)) {
		error("%s: username too long (%lu > max %lu)", __func__,
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ)ਲੜੀ_ਲੰਬਾਈ(pw->pw_name),
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ)ਆਕਾਰ(li->username) - 1);
		ਵਾਪਸ ਨਿਰਾ;
	}

	ਜੇ (getlast_ਇੰਦਰਾਜ(li))
		ਵਾਪਸ (li);
	ਨਹੀਂਤਾਂ
		ਵਾਪਸ (ਨਿਰਾ);
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
ਬਣਤਰ
logininfo *login_alloc_ਇੰਦਰਾਜ(pid_t pid, ਅਚਲ ਅੱਖਰ *username,
    ਅਚਲ ਅੱਖਰ *hostname, ਅਚਲ ਅੱਖਰ *ਸਤਰ)
{
	ਬਣਤਰ logininfo *newli;

	newli = xmalloc(ਆਕਾਰ(*newli));
	login_init_ਇੰਦਰਾਜ(newli, pid, username, hostname, ਸਤਰ);
	ਵਾਪਸ (newli);
}


/* login_free_entry(struct logininfo *)    - free struct memory */
ਖਾਲੀ
login_free_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li)
{
	ਮੁਕਤ(li);
}


/* login_init_entry(struct logininfo *, int, char*, char*, char*)
 *                                        - initialise a struct logininfo
 *
 * Populates a new struct logininfo, a data structure meant to carry
 * the information required to portably record login info.
 *
 * Returns: 1
 */
ਪੂਰਨ
login_init_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li, pid_t pid, ਅਚਲ ਅੱਖਰ *username,
    ਅਚਲ ਅੱਖਰ *hostname, ਅਚਲ ਅੱਖਰ *ਸਤਰ)
{
	ਬਣਤਰ passwd *pw;

	memset(li, 0, ਆਕਾਰ(*li));

	li->pid = pid;

	/* set the line information */
	ਜੇ (ਸਤਰ)
		ਸਤਰ_fullname(li->ਸਤਰ, ਸਤਰ, ਆਕਾਰ(li->ਸਤਰ));

	ਜੇ (username) {
		strlcpy(li->username, username, ਆਕਾਰ(li->username));
		pw = getpwnam(li->username);
		ਜੇ (pw == ਨਿਰਾ) {
			fatal("%s: Cannot find user \"%s\"", __func__,
			    li->username);
		}
		li->uid = pw->pw_uid;
	}

	ਜੇ (hostname)
		strlcpy(li->hostname, hostname, ਆਕਾਰ(li->hostname));

	ਵਾਪਸ (1);
}

/*
 * login_set_current_time(struct logininfo *)    - set the current time
 *
 * Set the current time in a logininfo structure. This function is
 * meant to eliminate the need to deal with system dependencies for
 * time handling.
 */
ਖਾਲੀ
login_ਸੈੱਟ_current_ਸਮਾਂ(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ timeval tv;

	gettimeofday(&tv, ਨਿਰਾ);

	li->tv_sec = tv.tv_sec;
	li->tv_usec = tv.tv_usec;
}

/* copy a sockaddr_* into our logininfo */
ਖਾਲੀ
login_ਸੈੱਟ_addr(ਬਣਤਰ logininfo *li, ਅਚਲ ਬਣਤਰ sockaddr *sa,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ sa_ਮਾਪ)
{
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ bufsize = sa_ਮਾਪ;

	/* make sure we don't overrun our union */
	ਜੇ (ਆਕਾਰ(li->hostaddr) < sa_ਮਾਪ)
		bufsize = ਆਕਾਰ(li->hostaddr);

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(&li->hostaddr.sa, sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/
ਪੂਰਨ
login_write(ਬਣਤਰ logininfo *li)
{
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
	ਜੇ (geteuid() != 0) {
		logit("Attempt to write login records by non-root user (aborting)");
		ਵਾਪਸ (1);
	}
#ਜੇ_ਅੰਤ

	/* set the timestamp */
	login_ਸੈੱਟ_current_ਸਮਾਂ(li);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LOGIN
	syslogin_write_ਇੰਦਰਾਜ(li);
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LASTLOG
	ਜੇ (li->type == LTYPE_LOGIN)
		lastlog_write_ਇੰਦਰਾਜ(li);
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_UTMP
	utmp_write_ਇੰਦਰਾਜ(li);
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_WTMP
	wtmp_write_ਇੰਦਰਾਜ(li);
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_UTMPX
	utmpx_write_ਇੰਦਰਾਜ(li);
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_WTMPX
	wtmpx_write_ਇੰਦਰਾਜ(li);
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_WTMPDB
	wtmpdb_write_ਇੰਦਰਾਜ(li);
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ CUSTOM_SYS_AUTH_ਰਿਕਾਰਡ_LOGIN
	ਜੇ (li->type == LTYPE_LOGIN &&
	    !sys_auth_ਰਿਕਾਰਡ_login(li->username,li->hostname,li->ਸਤਰ,
	    loginmsg))
		logit("Writing login record failed for %s", li->username);
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
	ਜੇ (li->type == LTYPE_LOGIN)
		audit_session_open(li);
	ਨਹੀਂਤਾਂ ਜੇ (li->type == LTYPE_LOGOUT)
		audit_session_close(li);
#ਜੇ_ਅੰਤ
	ਵਾਪਸ (0);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LOGIN_NEEDS_UTMPX
ਪੂਰਨ
login_utmp_only(ਬਣਤਰ logininfo *li)
{
	li->type = LTYPE_LOGIN;
	login_ਸੈੱਟ_current_ਸਮਾਂ(li);
# ifdef USE_UTMP
	utmp_write_ਇੰਦਰਾਜ(li);
# endif
# ifdef USE_WTMP
	wtmp_write_ਇੰਦਰਾਜ(li);
# endif
# ifdef USE_UTMPX
	utmpx_write_ਇੰਦਰਾਜ(li);
# endif
# ifdef USE_WTMPX
	wtmpx_write_ਇੰਦਰਾਜ(li);
# endif
	ਵਾਪਸ (0);
}
#ਜੇ_ਅੰਤ

/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
ਪੂਰਨ
getlast_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LASTLOG
	ਵਾਪਸ(lastlog_get_ਇੰਦਰਾਜ(li));
#ਨਹੀਂਤਾਂ /* !USE_LASTLOG */
#ਜੇ defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
	ਵਾਪਸ (utmpx_get_ਇੰਦਰਾਜ(li));
#ਜੇ_ਅੰਤ

#ਜੇ defined(DISABLE_LASTLOG)
	/* On some systems we shouldn't even try to obtain last login
	 * time, e.g. AIX */
	ਵਾਪਸ (0);
# elif defined(USE_WTMP) && \
    (defined(HAVE_ਸਮਾਂ_ਵਿੱਚ_UTMP) || defined(HAVE_TV_ਵਿੱਚ_UTMP))
	/* retrieve last login time from utmp */
	ਵਾਪਸ (wtmp_get_ਇੰਦਰਾਜ(li));
# elif defined(USE_WTMPX) && \
    (defined(HAVE_ਸਮਾਂ_ਵਿੱਚ_UTMPX) || defined(HAVE_TV_ਵਿੱਚ_UTMPX))
	/* If wtmp isn't available, try wtmpx */
	ਵਾਪਸ (wtmpx_get_ਇੰਦਰਾਜ(li));
# ਨਹੀਂਤਾਂ
	/* Give up: No means of retrieving last login time */
	ਵਾਪਸ (0);
# endif /* DISABLE_LASTLOG */
#ਜੇ_ਅੰਤ /* USE_LASTLOG */
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
ਅੱਖਰ *
ਸਤਰ_fullname(ਅੱਖਰ *dst, ਅਚਲ ਅੱਖਰ *src, u_int dstsize)
{
	memset(dst, '\0', dstsize);
	ਜੇ ((ਲੜੀ_ਤੁਲਨਾ(src, "/dev/", 5) == 0) || (dstsize < (ਲੜੀ_ਲੰਬਾਈ(src) + 5)))
		strlcpy(dst, src, dstsize);
	ਨਹੀਂਤਾਂ {
		strlcpy(dst, "/dev/", dstsize);
		strlcat(dst, src, dstsize);
	}
	ਵਾਪਸ (dst);
}

/* line_stripname(): strip the leading '/dev' if it exists, return dst */
ਅੱਖਰ *
ਸਤਰ_stripname(ਅੱਖਰ *dst, ਅਚਲ ਅੱਖਰ *src, ਪੂਰਨ dstsize)
{
	memset(dst, '\0', dstsize);
	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(src, "/dev/", 5) == 0)
		strlcpy(dst, src + 5, dstsize);
	ਨਹੀਂਤਾਂ
		strlcpy(dst, src, dstsize);
	ਵਾਪਸ (dst);
}

/*
 * line_abbrevname(): Return the abbreviated (usually four-character)
 * form of the line (Just use the last <dstsize> characters of the
 * full name.)
 *
 * NOTE: use strncpy because we do NOT necessarily want zero
 * termination
 */
ਅੱਖਰ *
ਸਤਰ_abbrevname(ਅੱਖਰ *dst, ਅਚਲ ਅੱਖਰ *src, ਪੂਰਨ dstsize)
{
	ਮਾਪ_t len;

	memset(dst, '\0', dstsize);

	ਜੇ (strcmp(src, "ssh:notty") == 0)
		ਵਾਪਸ dst;

	/* Always skip prefix if present */
	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(src, "/dev/", 5) == 0)
		src += 5;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_ABBREV_NO_TTY
	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(src, "tty", 3) == 0)
		src += 3;
#ਜੇ_ਅੰਤ

	len = ਲੜੀ_ਲੰਬਾਈ(src);

	ਜੇ (len > 0) {
		ਜੇ (((ਪੂਰਨ)len - dstsize) > 0)
			src +=  ((ਪੂਰਨ)len - dstsize);

		/* note: _don't_ change this to strlcpy */
		strncpy(dst, src, (ਮਾਪ_t)dstsize);
	}

	ਵਾਪਸ (dst);
}

/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#ਜੇ defined(USE_BTMP) || defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
ਖਾਲੀ
ਸੈੱਟ_utmp_ਸਮਾਂ(ਬਣਤਰ logininfo *li, ਬਣਤਰ utmp *ut)
{
# ਜੇ defined(HAVE_TV_ਵਿੱਚ_UTMP)
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_ਸਮਾਂ_ਵਿੱਚ_UTMP)
	ut->ut_ਸਮਾਂ = li->tv_sec;
# endif
}

ਖਾਲੀ
construct_utmp(ਬਣਤਰ logininfo *li,
		    ਬਣਤਰ utmp *ut)
{
# ifdef HAVE_ADDR_V6_ਵਿੱਚ_UTMP
	ਬਣਤਰ sockaddr_in6 *sa6;
# endif

	memset(ut, '\0', ਆਕਾਰ(*ut));

	/* First fill out fields used for both logins and logouts */

# ifdef HAVE_ID_ਵਿੱਚ_UTMP
	ਸਤਰ_abbrevname(ut->ut_id, li->ਸਤਰ, ਆਕਾਰ(ut->ut_id));
# endif

# ifdef HAVE_TYPE_ਵਿੱਚ_UTMP
	/* This is done here to keep utmp constants out of struct logininfo */
	ਚੋਣ (li->type) {
	ਹਾਲਤ LTYPE_FAILED:
		ut->ut_type = LOGIN_PROCESS;
		ਰੋਕੋ;
	ਹਾਲਤ LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		ਰੋਕੋ;
	ਹਾਲਤ LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		ਰੋਕੋ;
	}
# endif
	ਸੈੱਟ_utmp_ਸਮਾਂ(li, ut);

	ਸਤਰ_stripname(ut->ut_ਸਤਰ, li->ਸਤਰ, ਆਕਾਰ(ut->ut_ਸਤਰ));

# ifdef HAVE_PID_ਵਿੱਚ_UTMP
	ut->ut_pid = li->pid;
# endif

	/* If we're logging out, leave all other fields blank */
	ਜੇ (li->type == LTYPE_LOGOUT)
		ਵਾਪਸ;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

	/* Use strncpy because we don't necessarily want null termination */
	strncpy(ut->ut_name, li->username,
	    MIN_SIZEOF(ut->ut_name, li->username));
# ifdef HAVE_HOST_ਵਿੱਚ_UTMP
	strncpy(ut->ut_host, li->hostname,
	    MIN_SIZEOF(ut->ut_host, li->hostname));
# endif
# ifdef HAVE_ADDR_ਵਿੱਚ_UTMP
	/* this is just a 32-bit IP address */
	ਜੇ (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_ਵਿੱਚ.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_ਵਿੱਚ_UTMP
	/* this is just a 128-bit IPv6 address */
	ਜੇ (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((ਬਣਤਰ sockaddr_in6 *)&li->hostaddr.sa);
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(ut->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		ਜੇ (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			ut->ut_addr_v6[0] = ut->ut_addr_v6[3];
			ut->ut_addr_v6[1] = 0;
			ut->ut_addr_v6[2] = 0;
			ut->ut_addr_v6[3] = 0;
		}
	}
# endif
}
#ਜੇ_ਅੰਤ /* USE_BTMP || USE_UTMP || USE_WTMP || USE_LOGIN */

/**
 ** utmpx utility functions
 **
 ** These functions manipulate struct utmpx, accounting for system
 ** variations.
 **/

#ਜੇ defined(USE_UTMPX) || defined (USE_WTMPX)
/* build the utmpx structure */
ਖਾਲੀ
ਸੈੱਟ_utmpx_ਸਮਾਂ(ਬਣਤਰ logininfo *li, ਬਣਤਰ utmpx *utx)
{
# ਜੇ defined(HAVE_TV_ਵਿੱਚ_UTMPX)
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_ਸਮਾਂ_ਵਿੱਚ_UTMPX)
	utx->ut_ਸਮਾਂ = li->tv_sec;
# endif
}

ਖਾਲੀ
construct_utmpx(ਬਣਤਰ logininfo *li, ਬਣਤਰ utmpx *utx)
{
# ifdef HAVE_ADDR_V6_ਵਿੱਚ_UTMPX
	ਬਣਤਰ sockaddr_in6 *sa6;
#  endif
	memset(utx, '\0', ਆਕਾਰ(*utx));

# ifdef HAVE_ID_ਵਿੱਚ_UTMPX
	ਸਤਰ_abbrevname(utx->ut_id, li->ਸਤਰ, ਆਕਾਰ(utx->ut_id));
# endif

	/* this is done here to keep utmp constants out of loginrec.h */
	ਚੋਣ (li->type) {
	ਹਾਲਤ LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		ਰੋਕੋ;
	ਹਾਲਤ LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		ਰੋਕੋ;
	}
	ਸਤਰ_stripname(utx->ut_ਸਤਰ, li->ਸਤਰ, ਆਕਾਰ(utx->ut_ਸਤਰ));
	ਸੈੱਟ_utmpx_ਸਮਾਂ(li, utx);
	utx->ut_pid = li->pid;

	/* strncpy(): Don't necessarily want null termination */
	strncpy(utx->ut_user, li->username,
	    MIN_SIZEOF(utx->ut_user, li->username));

	ਜੇ (li->type == LTYPE_LOGOUT)
		ਵਾਪਸ;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

# ifdef HAVE_HOST_ਵਿੱਚ_UTMPX
	strncpy(utx->ut_host, li->hostname,
	    MIN_SIZEOF(utx->ut_host, li->hostname));
# endif
# ifdef HAVE_SS_ਵਿੱਚ_UTMPX
	utx->ut_ss = li->hostaddr.sa_storage;
# endif
# ifdef HAVE_ADDR_ਵਿੱਚ_UTMPX
	/* this is just a 32-bit IP address */
	ਜੇ (li->hostaddr.sa.sa_family == AF_INET)
		utx->ut_addr = li->hostaddr.sa_ਵਿੱਚ.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_ਵਿੱਚ_UTMPX
	/* this is just a 128-bit IPv6 address */
	ਜੇ (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((ਬਣਤਰ sockaddr_in6 *)&li->hostaddr.sa);
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(utx->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		ਜੇ (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			utx->ut_addr_v6[0] = utx->ut_addr_v6[3];
			utx->ut_addr_v6[1] = 0;
			utx->ut_addr_v6[2] = 0;
			utx->ut_addr_v6[3] = 0;
		}
	}
# endif
# ifdef HAVE_SYSLEN_ਵਿੱਚ_UTMPX
	/* ut_syslen is the length of the utx_host string */
	utx->ut_syslen = MINIMUM(ਲੜੀ_ਲੰਬਾਈ(li->hostname), ਆਕਾਰ(utx->ut_host));
# endif
}
#ਜੇ_ਅੰਤ /* USE_UTMPX || USE_WTMPX */

/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_UTMP

/* if we can, use pututline() etc. */
# ਜੇ !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
	defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
# endif


/* write a utmp entry with the system's help (pututline() and pals) */
# ifdef UTMP_USE_LIBRARY
ਸਥਿਰ ਪੂਰਨ
utmp_write_library(ਬਣਤਰ logininfo *li, ਬਣਤਰ utmp *ut)
{
	setutent();
	pututline(ut);
#  ifdef HAVE_ENDUTENT
	endutent();
#  endif
	ਵਾਪਸ (1);
}
# ਨਹੀਂਤਾਂ /* UTMP_USE_LIBRARY */

/*
 * Write a utmp entry direct to the file
 * This is a slightly modification of code in OpenBSD's login.c
 */
ਸਥਿਰ ਪੂਰਨ
utmp_write_ਸਿੱਧਾ(ਬਣਤਰ logininfo *li, ਬਣਤਰ utmp *ut)
{
	ਬਣਤਰ utmp old_ut;
	ਰਜਿਸਟਰ ਪੂਰਨ fd;
	ਪੂਰਨ tty;

	/* FIXME: (ATL) ttyslot() needs local implementation */

#ਜੇ defined(HAVE_GETTTYENT)
	ਬਣਤਰ ttyent *ty;

	tty=0;
	setttyent();
	ਜਦੋਂ (ਨਿਰਾ != (ty = getttyent())) {
		tty++;
		ਜੇ (!ਲੜੀ_ਤੁਲਨਾ(ty->ty_name, ut->ut_ਸਤਰ, ਆਕਾਰ(ut->ut_ਸਤਰ)))
			ਰੋਕੋ;
	}
	endttyent();

	ਜੇ (ਨਿਰਾ == ty) {
		logit_f("tty not found");
		ਵਾਪਸ (0);
	}
#ਨਹੀਂਤਾਂ /* FIXME */

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

#ਜੇ_ਅੰਤ /* HAVE_GETTTYENT */

	ਜੇ (tty > 0 && (fd = open(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		off_t pos, ret;

		pos = (off_t)tty * ਆਕਾਰ(ਬਣਤਰ utmp);
		ਜੇ ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			ਵਾਪਸ (0);
		}
		ਜੇ (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			ਵਾਪਸ (0);
		}
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		ਜੇ (atomicio(ਪਠ, fd, &old_ut, ਆਕਾਰ(old_ut)) == ਆਕਾਰ(old_ut) &&
		    (ut->ut_host[0] == '\0') && (old_ut.ut_host[0] != '\0') &&
		    (ਲੜੀ_ਤੁਲਨਾ(old_ut.ut_ਸਤਰ, ut->ut_ਸਤਰ, ਆਕਾਰ(ut->ut_ਸਤਰ)) == 0) &&
		    (ਲੜੀ_ਤੁਲਨਾ(old_ut.ut_name, ut->ut_name, ਆਕਾਰ(ut->ut_name)) == 0))
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(ut->ut_host, old_ut.ut_host, ਆਕਾਰ(ut->ut_host));

		ਜੇ ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			ਵਾਪਸ (0);
		}
		ਜੇ (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			ਵਾਪਸ (0);
		}
		ਜੇ (atomicio(vwrite, fd, ut, ਆਕਾਰ(*ut)) != ਆਕਾਰ(*ut)) {
			logit("%s: error writing %s: %s", __func__,
			    UTMP_FILE, strerror(errno));
			close(fd);
			ਵਾਪਸ (0);
		}

		close(fd);
		ਵਾਪਸ (1);
	} ਨਹੀਂਤਾਂ {
		ਵਾਪਸ (0);
	}
}
# endif /* UTMP_USE_LIBRARY */

ਸਥਿਰ ਪੂਰਨ
utmp_perform_login(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	ਜੇ (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		ਵਾਪਸ (0);
	}
# ਨਹੀਂਤਾਂ
	ਜੇ (!utmp_write_ਸਿੱਧਾ(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		ਵਾਪਸ (0);
	}
# endif
	ਵਾਪਸ (1);
}


ਸਥਿਰ ਪੂਰਨ
utmp_perform_logout(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	ਜੇ (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		ਵਾਪਸ (0);
	}
# ਨਹੀਂਤਾਂ
	ਜੇ (!utmp_write_ਸਿੱਧਾ(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		ਵਾਪਸ (0);
	}
# endif
	ਵਾਪਸ (1);
}


ਪੂਰਨ
utmp_write_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li)
{
	ਚੋਣ(li->type) {
	ਹਾਲਤ LTYPE_LOGIN:
		ਵਾਪਸ (utmp_perform_login(li));

	ਹਾਲਤ LTYPE_LOGOUT:
		ਵਾਪਸ (utmp_perform_logout(li));

	ਮੂਲ:
		logit_f("invalid type field");
		ਵਾਪਸ (0);
	}
}
#ਜੇ_ਅੰਤ /* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_UTMPX

/* if we have the wherewithal, use pututxline etc. */
# ਜੇ !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) && \
	defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
# endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
# ifdef UTMPX_USE_LIBRARY
ਸਥਿਰ ਪੂਰਨ
utmpx_write_library(ਬਣਤਰ logininfo *li, ਬਣਤਰ utmpx *utx)
{
	setutxent();
	pututxline(utx);

#  ifdef HAVE_ENDUTXENT
	endutxent();
#  endif
	ਵਾਪਸ (1);
}

# ਨਹੀਂਤਾਂ /* UTMPX_USE_LIBRARY */

/* write a utmp entry direct to the file */
ਸਥਿਰ ਪੂਰਨ
utmpx_write_ਸਿੱਧਾ(ਬਣਤਰ logininfo *li, ਬਣਤਰ utmpx *utx)
{
	logit_f("not implemented!");
	ਵਾਪਸ (0);
}
# endif /* UTMPX_USE_LIBRARY */

ਸਥਿਰ ਪੂਰਨ
utmpx_perform_login(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ utmpx utx;

	construct_utmpx(li, &utx);
# ifdef UTMPX_USE_LIBRARY
	ਜੇ (!utmpx_write_library(li, &utx)) {
		logit_f("utmp_write_library() failed");
		ਵਾਪਸ (0);
	}
# ਨਹੀਂਤਾਂ
	ਜੇ (!utmpx_write_ਸਿੱਧਾ(li, &utx)) {
		logit_f("utmp_write_direct() failed");
		ਵਾਪਸ (0);
	}
# endif
	ਵਾਪਸ (1);
}


ਸਥਿਰ ਪੂਰਨ
utmpx_perform_logout(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ utmpx utx;

	construct_utmpx(li, &utx);
# ifdef HAVE_ID_ਵਿੱਚ_UTMPX
	ਸਤਰ_abbrevname(utx.ut_id, li->ਸਤਰ, ਆਕਾਰ(utx.ut_id));
# endif
# ifdef HAVE_TYPE_ਵਿੱਚ_UTMPX
	utx.ut_type = DEAD_PROCESS;
# endif

# ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
# ਨਹੀਂਤਾਂ
	utmpx_write_ਸਿੱਧਾ(li, &utx);
# endif
	ਵਾਪਸ (1);
}

ਪੂਰਨ
utmpx_write_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li)
{
	ਚੋਣ(li->type) {
	ਹਾਲਤ LTYPE_LOGIN:
		ਵਾਪਸ (utmpx_perform_login(li));
	ਹਾਲਤ LTYPE_LOGOUT:
		ਵਾਪਸ (utmpx_perform_logout(li));
	ਮੂਲ:
		logit_f("invalid type field");
		ਵਾਪਸ (0);
	}
}
#ਜੇ_ਅੰਤ /* USE_UTMPX */


/**
 ** Low-level wtmp functions
 **/

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_WTMP

/*
 * Write a wtmp entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
ਸਥਿਰ ਪੂਰਨ
wtmp_write(ਬਣਤਰ logininfo *li, ਬਣਤਰ utmp *ut)
{
	ਬਣਤਰ stat buf;
	ਪੂਰਨ fd, ret = 1;

	ਜੇ ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem writing %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		ਵਾਪਸ (0);
	}
	ਜੇ (fstat(fd, &buf) == 0)
		ਜੇ (atomicio(vwrite, fd, ut, ਆਕਾਰ(*ut)) != ਆਕਾਰ(*ut)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMP_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);
	ਵਾਪਸ (ret);
}

ਸਥਿਰ ਪੂਰਨ
wtmp_perform_login(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ utmp ut;

	construct_utmp(li, &ut);
	ਵਾਪਸ (wtmp_write(li, &ut));
}


ਸਥਿਰ ਪੂਰਨ
wtmp_perform_logout(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ utmp ut;

	construct_utmp(li, &ut);
	ਵਾਪਸ (wtmp_write(li, &ut));
}


ਪੂਰਨ
wtmp_write_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li)
{
	ਚੋਣ(li->type) {
	ਹਾਲਤ LTYPE_LOGIN:
		ਵਾਪਸ (wtmp_perform_login(li));
	ਹਾਲਤ LTYPE_LOGOUT:
		ਵਾਪਸ (wtmp_perform_logout(li));
	ਮੂਲ:
		logit_f("invalid type field");
		ਵਾਪਸ (0);
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
ਸਥਿਰ ਪੂਰਨ
wtmp_islogin(ਬਣਤਰ logininfo *li, ਬਣਤਰ utmp *ut)
{
	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(li->username, ut->ut_name,
	    MIN_SIZEOF(li->username, ut->ut_name)) == 0) {
# ifdef HAVE_TYPE_ਵਿੱਚ_UTMP
		ਜੇ (ut->ut_type & USER_PROCESS)
			ਵਾਪਸ (1);
# ਨਹੀਂਤਾਂ
		ਵਾਪਸ (1);
# endif
	}
	ਵਾਪਸ (0);
}

ਪੂਰਨ
wtmp_get_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ stat st;
	ਬਣਤਰ utmp ut;
	ਪੂਰਨ fd, ਮਿਲਿਆ = 0;

	/* Clear the time entries in our logininfo */
	li->tv_sec = li->tv_usec = 0;

	ਜੇ ((fd = open(WTMP_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		ਵਾਪਸ (0);
	}
	ਜੇ (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		close(fd);
		ਵਾਪਸ (0);
	}

	/* Seek to the start of the last struct utmp */
	ਜੇ (lseek(fd, -(off_t)ਆਕਾਰ(ਬਣਤਰ utmp), SEEK_END) == -1) {
		/* Looks like we've got a fresh wtmp file */
		close(fd);
		ਵਾਪਸ (0);
	}

	ਜਦੋਂ (!ਮਿਲਿਆ) {
		ਜੇ (atomicio(ਪਠ, fd, &ut, ਆਕਾਰ(ut)) != ਆਕਾਰ(ut)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMP_FILE, strerror(errno));
			close (fd);
			ਵਾਪਸ (0);
		}
		ਜੇ (wtmp_islogin(li, &ut) ) {
			ਮਿਲਿਆ = 1;
			/*
			 * We've already checked for a time in struct
			 * utmp, in login_getlast()
			 */
# ifdef HAVE_ਸਮਾਂ_ਵਿੱਚ_UTMP
			li->tv_sec = ut.ut_ਸਮਾਂ;
# ਨਹੀਂਤਾਂ
#  ਜੇ HAVE_TV_ਵਿੱਚ_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
# endif
			ਸਤਰ_fullname(li->ਸਤਰ, ut.ut_ਸਤਰ,
			    MIN_SIZEOF(li->ਸਤਰ, ut.ut_ਸਤਰ));
# ifdef HAVE_HOST_ਵਿੱਚ_UTMP
			strlcpy(li->hostname, ut.ut_host,
			    MIN_SIZEOF(li->hostname, ut.ut_host));
# endif
			ਜਾਰੀ;
		}
		/* Seek back 2 x struct utmp */
		ਜੇ (lseek(fd, -(off_t)(2 * ਆਕਾਰ(ਬਣਤਰ utmp)), SEEK_CUR) == -1) {
			/* We've found the start of the file, so quit */
			close(fd);
			ਵਾਪਸ (0);
		}
	}

	/* We found an entry. Tidy up and return */
	close(fd);
	ਵਾਪਸ (1);
}
# endif /* USE_WTMP */


/**
 ** Low-level wtmpx functions
 **/

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_WTMPX
/*
 * Write a wtmpx entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
ਸਥਿਰ ਪੂਰਨ
wtmpx_write(ਬਣਤਰ logininfo *li, ਬਣਤਰ utmpx *utx)
{
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_UPDWTMPX
	ਬਣਤਰ stat buf;
	ਪੂਰਨ fd, ret = 1;

	ਜੇ ((fd = open(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		ਵਾਪਸ (0);
	}

	ਜੇ (fstat(fd, &buf) == 0)
		ਜੇ (atomicio(vwrite, fd, utx, ਆਕਾਰ(*utx)) != ਆਕਾਰ(*utx)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);

	ਵਾਪਸ (ret);
#ਨਹੀਂਤਾਂ
	updwtmpx(WTMPX_FILE, utx);
	ਵਾਪਸ (1);
#ਜੇ_ਅੰਤ
}


ਸਥਿਰ ਪੂਰਨ
wtmpx_perform_login(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ utmpx utx;

	construct_utmpx(li, &utx);
	ਵਾਪਸ (wtmpx_write(li, &utx));
}


ਸਥਿਰ ਪੂਰਨ
wtmpx_perform_logout(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ utmpx utx;

	construct_utmpx(li, &utx);
	ਵਾਪਸ (wtmpx_write(li, &utx));
}


ਪੂਰਨ
wtmpx_write_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li)
{
	ਚੋਣ(li->type) {
	ਹਾਲਤ LTYPE_LOGIN:
		ਵਾਪਸ (wtmpx_perform_login(li));
	ਹਾਲਤ LTYPE_LOGOUT:
		ਵਾਪਸ (wtmpx_perform_logout(li));
	ਮੂਲ:
		logit_f("invalid type field");
		ਵਾਪਸ (0);
	}
}

/* Please see the notes above wtmp_islogin() for information about the
   next two functions */

/* Return true if this wtmpx entry indicates a login */
ਸਥਿਰ ਪੂਰਨ
wtmpx_islogin(ਬਣਤਰ logininfo *li, ਬਣਤਰ utmpx *utx)
{
	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(li->username, utx->ut_user,
	    MIN_SIZEOF(li->username, utx->ut_user)) == 0 ) {
# ifdef HAVE_TYPE_ਵਿੱਚ_UTMPX
		ਜੇ (utx->ut_type == USER_PROCESS)
			ਵਾਪਸ (1);
# ਨਹੀਂਤਾਂ
		ਵਾਪਸ (1);
# endif
	}
	ਵਾਪਸ (0);
}


ਪੂਰਨ
wtmpx_get_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ stat st;
	ਬਣਤਰ utmpx utx;
	ਪੂਰਨ fd, ਮਿਲਿਆ=0;

	/* Clear the time entries */
	li->tv_sec = li->tv_usec = 0;

	ਜੇ ((fd = open(WTMPX_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		ਵਾਪਸ (0);
	}
	ਜੇ (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		close(fd);
		ਵਾਪਸ (0);
	}

	/* Seek to the start of the last struct utmpx */
	ਜੇ (lseek(fd, -(off_t)ਆਕਾਰ(ਬਣਤਰ utmpx), SEEK_END) == -1 ) {
		/* probably a newly rotated wtmpx file */
		close(fd);
		ਵਾਪਸ (0);
	}

	ਜਦੋਂ (!ਮਿਲਿਆ) {
		ਜੇ (atomicio(ਪਠ, fd, &utx, ਆਕਾਰ(utx)) != ਆਕਾਰ(utx)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			close (fd);
			ਵਾਪਸ (0);
		}
		/*
		 * Logouts are recorded as a blank username on a particular
		 * line. So, we just need to find the username in struct utmpx
		 */
		ਜੇ (wtmpx_islogin(li, &utx)) {
			ਮਿਲਿਆ = 1;
# ਜੇ defined(HAVE_TV_ਵਿੱਚ_UTMPX)
			li->tv_sec = utx.ut_tv.tv_sec;
# elif defined(HAVE_ਸਮਾਂ_ਵਿੱਚ_UTMPX)
			li->tv_sec = utx.ut_ਸਮਾਂ;
# endif
			ਸਤਰ_fullname(li->ਸਤਰ, utx.ut_ਸਤਰ, ਆਕਾਰ(li->ਸਤਰ));
# ਜੇ defined(HAVE_HOST_ਵਿੱਚ_UTMPX)
			strlcpy(li->hostname, utx.ut_host,
			    MIN_SIZEOF(li->hostname, utx.ut_host));
# endif
			ਜਾਰੀ;
		}
		ਜੇ (lseek(fd, -(off_t)(2 * ਆਕਾਰ(ਬਣਤਰ utmpx)), SEEK_CUR) == -1) {
			close(fd);
			ਵਾਪਸ (0);
		}
	}

	close(fd);
	ਵਾਪਸ (1);
}
#ਜੇ_ਅੰਤ /* USE_WTMPX */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_WTMPDB
ਸਥਿਰ ਪੂਰਨ
wtmpdb_perform_login(ਬਣਤਰ logininfo *li)
{
	uint64_t login_ਸਮਾਂ = li->tv_sec * ((uint64_t) 1000000ULL) +
	    li->tv_usec;
	ਅਚਲ ਅੱਖਰ *tty;

	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(li->ਸਤਰ, "/dev/", 5) == 0)
		tty = &(li->ਸਤਰ[5]);
	ਨਹੀਂਤਾਂ
		tty = li->ਸਤਰ;

	li->wtmpdb_id = wtmpdb_login(ਨਿਰਾ, USER_PROCESS, li->username,
	    login_ਸਮਾਂ, tty, li->hostname, 0, 0);

	ਜੇ (li->wtmpdb_id < 0)
		ਵਾਪਸ (0);

	ਵਾਪਸ (1);
}

ਸਥਿਰ ਪੂਰਨ
wtmpdb_perform_logout(ਬਣਤਰ logininfo *li)
{
	uint64_t logout_ਸਮਾਂ = li->tv_sec * ((uint64_t) 1000000ULL) +
	   li->tv_usec;

	ਜੇ (li->wtmpdb_id == 0) {
		ਅਚਲ ਅੱਖਰ *tty;

		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(li->ਸਤਰ, "/dev/", 5) == 0)
			tty = &(li->ਸਤਰ[5]);
		ਨਹੀਂਤਾਂ
			tty = li->ਸਤਰ;

		li->wtmpdb_id = wtmpdb_get_id(ਨਿਰਾ, tty, ਨਿਰਾ);
	}
	wtmpdb_logout(ਨਿਰਾ, li->wtmpdb_id, logout_ਸਮਾਂ, ਨਿਰਾ);

	ਵਾਪਸ (1);
}

ਪੂਰਨ
wtmpdb_write_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li)
{
	ਚੋਣ(li->type) {
	ਹਾਲਤ LTYPE_LOGIN:
		ਵਾਪਸ (wtmpdb_perform_login(li));
	ਹਾਲਤ LTYPE_LOGOUT:
		ਵਾਪਸ (wtmpdb_perform_logout(li));
	ਮੂਲ:
		logit_f("invalid type field");
		ਵਾਪਸ (0);
	}
}
#ਜੇ_ਅੰਤ

/**
 ** Low-level libutil login() functions
 **/

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LOGIN
ਸਥਿਰ ਪੂਰਨ
syslogin_perform_login(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ utmp *ut;

	ut = xmalloc(ਆਕਾਰ(*ut));
	construct_utmp(li, ut);
	login(ut);
	ਮੁਕਤ(ut);

	ਵਾਪਸ (1);
}

ਸਥਿਰ ਪੂਰਨ
syslogin_perform_logout(ਬਣਤਰ logininfo *li)
{
# ifdef HAVE_LOGOUT
	ਅੱਖਰ ਸਤਰ[UT_LINESIZE];

	(ਖਾਲੀ)ਸਤਰ_stripname(ਸਤਰ, li->ਸਤਰ, ਆਕਾਰ(ਸਤਰ));

	ਜੇ (!logout(ਸਤਰ))
		logit_f("logout() returned an error");
#  ifdef HAVE_LOGWTMP
	ਨਹੀਂਤਾਂ
		logwtmp(ਸਤਰ, "", "");
#  endif
	/* FIXME: (ATL - if the need arises) What to do if we have
	 * login, but no logout?  what if logout but no logwtmp? All
	 * routines are in libutil so they should all be there,
	 * but... */
# endif
	ਵਾਪਸ (1);
}

ਪੂਰਨ
syslogin_write_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li)
{
	ਚੋਣ (li->type) {
	ਹਾਲਤ LTYPE_LOGIN:
		ਵਾਪਸ (syslogin_perform_login(li));
	ਹਾਲਤ LTYPE_LOGOUT:
		ਵਾਪਸ (syslogin_perform_logout(li));
	ਮੂਲ:
		logit_f("Invalid type field");
		ਵਾਪਸ (0);
	}
}
#ਜੇ_ਅੰਤ /* USE_LOGIN */

/* end of file log-syslogin.c */

/**
 ** Low-level lastlog functions
 **/

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LASTLOG

#ਜੇ !defined(LASTLOG_WRITE_PUTUTXLINE) || !defined(HAVE_GETLASTLOGXBYNAME)
/* open the file (using filemode) and seek to the login entry */
ਸਥਿਰ ਪੂਰਨ
lastlog_openseek(ਬਣਤਰ logininfo *li, ਪੂਰਨ *fd, ਪੂਰਨ filemode)
{
	off_t ਵਿੱਥ;
	ਅੱਖਰ lastlog_file[1024];
	ਬਣਤਰ stat st;

	ਜੇ (stat(LASTLOG_FILE, &st) != 0) {
		logit("%s: Couldn't stat %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		ਵਾਪਸ (0);
	}
	ਜੇ (S_ISDIR(st.st_mode)) {
		snprintf(lastlog_file, ਆਕਾਰ(lastlog_file), "%s/%s",
		    LASTLOG_FILE, li->username);
	} ਨਹੀਂਤਾਂ ਜੇ (S_ISREG(st.st_mode)) {
		strlcpy(lastlog_file, LASTLOG_FILE, ਆਕਾਰ(lastlog_file));
	} ਨਹੀਂਤਾਂ {
		logit("%s: %.100s is not a file or directory!", __func__,
		    LASTLOG_FILE);
		ਵਾਪਸ (0);
	}

	*fd = open(lastlog_file, filemode, 0600);
	ਜੇ (*fd < 0) {
		debug("%s: Couldn't open %s: %s", __func__,
		    lastlog_file, strerror(errno));
		ਵਾਪਸ (0);
	}

	ਜੇ (S_ISREG(st.st_mode)) {
		/* find this uid's offset in the lastlog file */
		ਵਿੱਥ = (off_t) ((u_long)li->uid * ਆਕਾਰ(ਬਣਤਰ lastlog));

		ਜੇ (lseek(*fd, ਵਿੱਥ, SEEK_SET) != ਵਿੱਥ) {
			logit("%s: %s->lseek(): %s", __func__,
			    lastlog_file, strerror(errno));
			close(*fd);
			ਵਾਪਸ (0);
		}
	}

	ਵਾਪਸ (1);
}
#ਜੇ_ਅੰਤ /* !LASTLOG_WRITE_PUTUTXLINE || !HAVE_GETLASTLOGXBYNAME */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LASTLOG_WRITE_PUTUTXLINE
ਪੂਰਨ
lastlog_write_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li)
{
	ਚੋਣ(li->type) {
	ਹਾਲਤ LTYPE_LOGIN:
		ਵਾਪਸ 1; /* lastlog written by pututxline */
	ਮੂਲ:
		logit("lastlog_write_entry: Invalid type field");
		ਵਾਪਸ 0;
	}
}
#ਨਹੀਂਤਾਂ /* LASTLOG_WRITE_PUTUTXLINE */
ਪੂਰਨ
lastlog_write_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ lastlog ਆਖਰੀ;
	ਪੂਰਨ fd;

	ਚੋਣ(li->type) {
	ਹਾਲਤ LTYPE_LOGIN:
		/* create our struct lastlog */
		memset(&ਆਖਰੀ, '\0', ਆਕਾਰ(ਆਖਰੀ));
		ਸਤਰ_stripname(ਆਖਰੀ.ll_ਸਤਰ, li->ਸਤਰ, ਆਕਾਰ(ਆਖਰੀ.ll_ਸਤਰ));
		strlcpy(ਆਖਰੀ.ll_host, li->hostname,
		    MIN_SIZEOF(ਆਖਰੀ.ll_host, li->hostname));
		ਆਖਰੀ.ll_ਸਮਾਂ = li->tv_sec;

		ਜੇ (!lastlog_openseek(li, &fd, O_RDWR|O_CREAT))
			ਵਾਪਸ (0);

		/* write the entry */
		ਜੇ (atomicio(vwrite, fd, &ਆਖਰੀ, ਆਕਾਰ(ਆਖਰੀ)) != ਆਕਾਰ(ਆਖਰੀ)) {
			close(fd);
			logit("%s: Error writing to %s: %s", __func__,
			    LASTLOG_FILE, strerror(errno));
			ਵਾਪਸ (0);
		}

		close(fd);
		ਵਾਪਸ (1);
	ਮੂਲ:
		logit_f("Invalid type field");
		ਵਾਪਸ (0);
	}
}
#ਜੇ_ਅੰਤ /* LASTLOG_WRITE_PUTUTXLINE */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_GETLASTLOGXBYNAME
ਪੂਰਨ
lastlog_get_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ lastlogx l, *ll;

	ਜੇ ((ll = getlastlogxbyname(li->username, &l)) == ਨਿਰਾ) {
		memset(&l, '\0', ਆਕਾਰ(l));
		ll = &l;
	}
	ਸਤਰ_fullname(li->ਸਤਰ, ll->ll_ਸਤਰ, ਆਕਾਰ(li->ਸਤਰ));
	strlcpy(li->hostname, ll->ll_host,
		MIN_SIZEOF(li->hostname, ll->ll_host));
	li->tv_sec = ll->ll_tv.tv_sec;
	li->tv_usec = ll->ll_tv.tv_usec;
	ਵਾਪਸ (1);
}
#ਨਹੀਂਤਾਂ /* HAVE_GETLASTLOGXBYNAME */
ਪੂਰਨ
lastlog_get_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ lastlog ਆਖਰੀ;
	ਪੂਰਨ fd, ret;

	ਜੇ (!lastlog_openseek(li, &fd, O_RDONLY))
		ਵਾਪਸ (0);

	ret = atomicio(ਪਠ, fd, &ਆਖਰੀ, ਆਕਾਰ(ਆਖਰੀ));
	close(fd);

	ਚੋਣ (ret) {
	ਹਾਲਤ 0:
		memset(&ਆਖਰੀ, '\0', ਆਕਾਰ(ਆਖਰੀ));
		/* FALLTHRU */
	ਹਾਲਤ ਆਕਾਰ(ਆਖਰੀ):
		ਸਤਰ_fullname(li->ਸਤਰ, ਆਖਰੀ.ll_ਸਤਰ, ਆਕਾਰ(li->ਸਤਰ));
		strlcpy(li->hostname, ਆਖਰੀ.ll_host,
		    MIN_SIZEOF(li->hostname, ਆਖਰੀ.ll_host));
		li->tv_sec = ਆਖਰੀ.ll_ਸਮਾਂ;
		ਵਾਪਸ (1);
	ਹਾਲਤ -1:
		error("%s: Error reading from %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		ਵਾਪਸ (0);
	ਮੂਲ:
		error("%s: Error reading from %s: Expecting %d, got %d",
		    __func__, LASTLOG_FILE, (ਪੂਰਨ)ਆਕਾਰ(ਆਖਰੀ), ret);
		ਵਾਪਸ (0);
	}

	/* NOTREACHED */
	ਵਾਪਸ (0);
}
#ਜੇ_ਅੰਤ /* HAVE_GETLASTLOGXBYNAME */
#ਜੇ_ਅੰਤ /* USE_LASTLOG */

#ਜੇ defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
ਪੂਰਨ
utmpx_get_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li)
{
	ਬਣਤਰ utmpx *utx;

	ਜੇ (setutxdb(UTXDB_LASTLOGIN, ਨਿਰਾ) != 0)
		ਵਾਪਸ (0);
	utx = getutxuser(li->username);
	ਜੇ (utx == ਨਿਰਾ) {
		endutxent();
		ਵਾਪਸ (0);
	}

	ਸਤਰ_fullname(li->ਸਤਰ, utx->ut_ਸਤਰ,
	    MIN_SIZEOF(li->ਸਤਰ, utx->ut_ਸਤਰ));
	strlcpy(li->hostname, utx->ut_host,
	    MIN_SIZEOF(li->hostname, utx->ut_host));
	li->tv_sec = utx->ut_tv.tv_sec;
	li->tv_usec = utx->ut_tv.tv_usec;
	endutxent();
	ਵਾਪਸ (1);
}
#ਜੇ_ਅੰਤ /* USE_UTMPX && HAVE_SETUTXDB && UTXDB_LASTLOGIN && HAVE_GETUTXUSER */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_BTMP
/*
 * Logs failed login attempts in _PATH_BTMP if that exists.
 * The most common login failure is to give password instead of username.
 * So the _PATH_BTMP file is checked for the correct permission, so that only
 * root can read it.
 */
ਖਾਲੀ
ਰਿਕਾਰਡ_failed_login(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *username, ਅਚਲ ਅੱਖਰ *hostname,
    ਅਚਲ ਅੱਖਰ *ttyn)
{
	ਪੂਰਨ fd;
	ਬਣਤਰ utmp ut;
	ਬਣਤਰ logininfo li;
	socklen_t fromlen = ਆਕਾਰ(li.hostaddr);
	time_t t;
	ਬਣਤਰ stat fst;

	ਜੇ (geteuid() != 0)
		ਵਾਪਸ;
	ਜੇ ((fd = open(ਰਸਤਾ_BTMP, O_WRONLY | O_APPEND)) < 0) {
		debug("Unable to open the btmp file %s: %s", ਰਸਤਾ_BTMP,
		    strerror(errno));
		ਵਾਪਸ;
	}
	ਜੇ (fstat(fd, &fst) < 0) {
		logit("%s: fstat of %s failed: %s", __func__, ਰਸਤਾ_BTMP,
		    strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((fst.st_mode & (S_IXGRP | S_IRWXO)) || fst.st_uid != 0) {
		logit("Excess permission or bad ownership on file %s",
		    ਰਸਤਾ_BTMP);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Construct a logininfo and turn it into a utmp */
	memset(&li, 0, ਆਕਾਰ(li));
	li.type = LTYPE_FAILED;
	li.pid = getpid();
	strlcpy(li.ਸਤਰ, "ssh:notty", ਆਕਾਰ(li.ਸਤਰ));
	strlcpy(li.username, username, ਆਕਾਰ(li.username));
	strlcpy(li.hostname, hostname, ਆਕਾਰ(li.hostname));
	time(&t);
	li.tv_sec = t > 0 ? (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ)t : 0;
	ਜੇ (ssh_packet_connection_is_on_socket(ssh)) {
		(ਖਾਲੀ)getpeername(ssh_packet_get_connection_ਵਿੱਚ(ssh),
		    &li.hostaddr.sa, &fromlen);
	}
	construct_utmp(&li, &ut);

	ਜੇ (atomicio(vwrite, fd, &ut, ਆਕਾਰ(ut)) != ਆਕਾਰ(ut)) {
		error("Failed to write to %s: %s", ਰਸਤਾ_BTMP,
		    strerror(errno));
	}
ਬਾਹਰਲਾ:
	close(fd);
}
#ਜੇ_ਅੰਤ	/* USE_BTMP */
