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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/time.h>

#அந்தர்பாவ <netinet/in.h>

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "loginrec.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "misc.h"

# include <util.h>

#ifdef USE_WTMPDB
# include <wtmpdb.h>
#endif

/**
 ** prototypes for helper functions in this file
 **/

#எனில் HAVE_UTMP_H
வெறுமை set_utmp_time(கட்டமைப்பு logininfo *li, கட்டமைப்பு utmp *ut);
வெறுமை construct_utmp(கட்டமைப்பு logininfo *li, கட்டமைப்பு utmp *ut);
#endif

#ifdef HAVE_UTMPX_H
வெறுமை set_utmpx_time(கட்டமைப்பு logininfo *li, கட்டமைப்பு utmpx *ut);
வெறுமை construct_utmpx(கட்டமைப்பு logininfo *li, கட்டமைப்பு utmpx *ut);
#endif

முழு utmp_write_entry(கட்டமைப்பு logininfo *li);
முழு utmpx_write_entry(கட்டமைப்பு logininfo *li);
முழு wtmp_write_entry(கட்டமைப்பு logininfo *li);
முழு wtmpx_write_entry(கட்டமைப்பு logininfo *li);
முழு lastlog_write_entry(கட்டமைப்பு logininfo *li);
முழு syslogin_write_entry(கட்டமைப்பு logininfo *li);
#ifdef USE_WTMPDB
முழு wtmpdb_write_entry(கட்டமைப்பு logininfo *li);
#endif

முழு getlast_entry(கட்டமைப்பு logininfo *li);
முழு lastlog_get_entry(கட்டமைப்பு logininfo *li);
முழு utmpx_get_entry(கட்டமைப்பு logininfo *li);
முழு wtmp_get_entry(கட்டமைப்பு logininfo *li);
முழு wtmpx_get_entry(கட்டமைப்பு logininfo *li);

வெளி கட்டமைப்பு sshbuf *loginmsg;

/* pick the shortest string */
#define MIN_SIZEOF(s1,s2) (அளவு(s1) < அளவு(s2) ? அளவு(s1) : அளவு(s2))

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
முழு
login_login(கட்டமைப்பு logininfo *li)
{
	li->type = LTYPE_LOGIN;
	திரும்பு (login_write(li));
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
முழு
login_logout(கட்டமைப்பு logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	திரும்பு (login_write(li));
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
unsigned முழு
login_get_lastlog_time(மாறிலி uid_t uid)
{
	கட்டமைப்பு logininfo li;

	எனில் (login_get_lastlog(&li, uid))
		திரும்பு (li.tv_sec);
	இல்லையெனில்
		திரும்பு (0);
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
கட்டமைப்பு logininfo *
login_get_lastlog(கட்டமைப்பு logininfo *li, மாறிலி uid_t uid)
{
	கட்டமைப்பு passwd *pw;

	memset(li, '\0', அளவு(*li));
	li->uid = uid;

	/*
	 * If we don't have a 'real' lastlog, we need the username to
	 * reliably search wtmp(x) for the last login (see
	 * wtmp_get_entry().)
	 */
	pw = getpwuid(uid);
	எனில் (pw == வெற்று)
		fatal("%s: Cannot find account for uid %ld", __func__,
		    (long)uid);

	எனில் (strlcpy(li->username, pw->pw_name, அளவு(li->username)) >=
	    அளவு(li->username)) {
		error("%s: username too long (%lu > max %lu)", __func__,
		    (unsigned long)strlen(pw->pw_name),
		    (unsigned long)அளவு(li->username) - 1);
		திரும்பு வெற்று;
	}

	எனில் (getlast_entry(li))
		திரும்பு (li);
	இல்லையெனில்
		திரும்பு (வெற்று);
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
கட்டமைப்பு
logininfo *login_alloc_entry(pid_t pid, மாறிலி எழுத்து *username,
    மாறிலி எழுத்து *hostname, மாறிலி எழுத்து *வரி)
{
	கட்டமைப்பு logininfo *newli;

	newli = xmalloc(அளவு(*newli));
	login_init_entry(newli, pid, username, hostname, வரி);
	திரும்பு (newli);
}


/* login_free_entry(struct logininfo *)    - free struct memory */
வெறுமை
login_free_entry(கட்டமைப்பு logininfo *li)
{
	விடுவி(li);
}


/* login_init_entry(struct logininfo *, int, char*, char*, char*)
 *                                        - initialise a struct logininfo
 *
 * Populates a new struct logininfo, a data structure meant to carry
 * the information required to portably record login info.
 *
 * Returns: 1
 */
முழு
login_init_entry(கட்டமைப்பு logininfo *li, pid_t pid, மாறிலி எழுத்து *username,
    மாறிலி எழுத்து *hostname, மாறிலி எழுத்து *வரி)
{
	கட்டமைப்பு passwd *pw;

	memset(li, 0, அளவு(*li));

	li->pid = pid;

	/* set the line information */
	எனில் (வரி)
		வரி_fullname(li->வரி, வரி, அளவு(li->வரி));

	எனில் (username) {
		strlcpy(li->username, username, அளவு(li->username));
		pw = getpwnam(li->username);
		எனில் (pw == வெற்று) {
			fatal("%s: Cannot find user \"%s\"", __func__,
			    li->username);
		}
		li->uid = pw->pw_uid;
	}

	எனில் (hostname)
		strlcpy(li->hostname, hostname, அளவு(li->hostname));

	திரும்பு (1);
}

/*
 * login_set_current_time(struct logininfo *)    - set the current time
 *
 * Set the current time in a logininfo structure. This function is
 * meant to eliminate the need to deal with system dependencies for
 * time handling.
 */
வெறுமை
login_set_current_time(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு timeval tv;

	gettimeofday(&tv, வெற்று);

	li->tv_sec = tv.tv_sec;
	li->tv_usec = tv.tv_usec;
}

/* copy a sockaddr_* into our logininfo */
வெறுமை
login_set_addr(கட்டமைப்பு logininfo *li, மாறிலி கட்டமைப்பு sockaddr *sa,
    மாறிலி unsigned முழு sa_size)
{
	unsigned முழு bufsize = sa_size;

	/* make sure we don't overrun our union */
	எனில் (அளவு(li->hostaddr) < sa_size)
		bufsize = அளவு(li->hostaddr);

	memcpy(&li->hostaddr.sa, sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/
முழு
login_write(கட்டமைப்பு logininfo *li)
{
#ifndef HAVE_CYGWIN
	எனில் (geteuid() != 0) {
		logit("Attempt to write login records by non-root user (aborting)");
		திரும்பு (1);
	}
#endif

	/* set the timestamp */
	login_set_current_time(li);
#ifdef USE_LOGIN
	syslogin_write_entry(li);
#endif
#ifdef USE_LASTLOG
	எனில் (li->type == LTYPE_LOGIN)
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
	எனில் (li->type == LTYPE_LOGIN &&
	    !sys_auth_record_login(li->username,li->hostname,li->வரி,
	    loginmsg))
		logit("Writing login record failed for %s", li->username);
#endif
#ifdef SSH_AUDIT_EVENTS
	எனில் (li->type == LTYPE_LOGIN)
		audit_session_open(li);
	இல்லையெனில் எனில் (li->type == LTYPE_LOGOUT)
		audit_session_close(li);
#endif
	திரும்பு (0);
}

#ifdef LOGIN_NEEDS_UTMPX
முழு
login_utmp_only(கட்டமைப்பு logininfo *li)
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
	திரும்பு (0);
}
#endif

/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
முழு
getlast_entry(கட்டமைப்பு logininfo *li)
{
#ifdef USE_LASTLOG
	திரும்பு(lastlog_get_entry(li));
#இல்லையெனில் /* !USE_LASTLOG */
#எனில் defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
	திரும்பு (utmpx_get_entry(li));
#endif

#எனில் defined(DISABLE_LASTLOG)
	/* On some systems we shouldn't even try to obtain last login
	 * time, e.g. AIX */
	திரும்பு (0);
# elif defined(USE_WTMP) && \
    (defined(HAVE_TIME_IN_UTMP) || defined(HAVE_TV_IN_UTMP))
	/* retrieve last login time from utmp */
	திரும்பு (wtmp_get_entry(li));
# elif defined(USE_WTMPX) && \
    (defined(HAVE_TIME_IN_UTMPX) || defined(HAVE_TV_IN_UTMPX))
	/* If wtmp isn't available, try wtmpx */
	திரும்பு (wtmpx_get_entry(li));
# இல்லையெனில்
	/* Give up: No means of retrieving last login time */
	திரும்பு (0);
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
எழுத்து *
வரி_fullname(எழுத்து *dst, மாறிலி எழுத்து *src, u_int dstsize)
{
	memset(dst, '\0', dstsize);
	எனில் ((strncmp(src, "/dev/", 5) == 0) || (dstsize < (strlen(src) + 5)))
		strlcpy(dst, src, dstsize);
	இல்லையெனில் {
		strlcpy(dst, "/dev/", dstsize);
		strlcat(dst, src, dstsize);
	}
	திரும்பு (dst);
}

/* line_stripname(): strip the leading '/dev' if it exists, return dst */
எழுத்து *
வரி_stripname(எழுத்து *dst, மாறிலி எழுத்து *src, முழு dstsize)
{
	memset(dst, '\0', dstsize);
	எனில் (strncmp(src, "/dev/", 5) == 0)
		strlcpy(dst, src + 5, dstsize);
	இல்லையெனில்
		strlcpy(dst, src, dstsize);
	திரும்பு (dst);
}

/*
 * line_abbrevname(): Return the abbreviated (usually four-character)
 * form of the line (Just use the last <dstsize> characters of the
 * full name.)
 *
 * NOTE: use strncpy because we do NOT necessarily want zero
 * termination
 */
எழுத்து *
வரி_abbrevname(எழுத்து *dst, மாறிலி எழுத்து *src, முழு dstsize)
{
	size_t len;

	memset(dst, '\0', dstsize);

	எனில் (strcmp(src, "ssh:notty") == 0)
		திரும்பு dst;

	/* Always skip prefix if present */
	எனில் (strncmp(src, "/dev/", 5) == 0)
		src += 5;

#ifdef WITH_ABBREV_NO_TTY
	எனில் (strncmp(src, "tty", 3) == 0)
		src += 3;
#endif

	len = strlen(src);

	எனில் (len > 0) {
		எனில் (((முழு)len - dstsize) > 0)
			src +=  ((முழு)len - dstsize);

		/* note: _don't_ change this to strlcpy */
		strncpy(dst, src, (size_t)dstsize);
	}

	திரும்பு (dst);
}

/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#எனில் defined(USE_BTMP) || defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
வெறுமை
set_utmp_time(கட்டமைப்பு logininfo *li, கட்டமைப்பு utmp *ut)
{
# எனில் defined(HAVE_TV_IN_UTMP)
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMP)
	ut->ut_time = li->tv_sec;
# endif
}

வெறுமை
construct_utmp(கட்டமைப்பு logininfo *li,
		    கட்டமைப்பு utmp *ut)
{
# ifdef HAVE_ADDR_V6_IN_UTMP
	கட்டமைப்பு sockaddr_in6 *sa6;
# endif

	memset(ut, '\0', அளவு(*ut));

	/* First fill out fields used for both logins and logouts */

# ifdef HAVE_ID_IN_UTMP
	வரி_abbrevname(ut->ut_id, li->வரி, அளவு(ut->ut_id));
# endif

# ifdef HAVE_TYPE_IN_UTMP
	/* This is done here to keep utmp constants out of struct logininfo */
	தேர்வு (li->type) {
	நிலை LTYPE_FAILED:
		ut->ut_type = LOGIN_PROCESS;
		நிறுத்து;
	நிலை LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		நிறுத்து;
	நிலை LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		நிறுத்து;
	}
# endif
	set_utmp_time(li, ut);

	வரி_stripname(ut->ut_வரி, li->வரி, அளவு(ut->ut_வரி));

# ifdef HAVE_PID_IN_UTMP
	ut->ut_pid = li->pid;
# endif

	/* If we're logging out, leave all other fields blank */
	எனில் (li->type == LTYPE_LOGOUT)
		திரும்பு;

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
	எனில் (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMP
	/* this is just a 128-bit IPv6 address */
	எனில் (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((கட்டமைப்பு sockaddr_in6 *)&li->hostaddr.sa);
		memcpy(ut->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		எனில் (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
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

#எனில் defined(USE_UTMPX) || defined (USE_WTMPX)
/* build the utmpx structure */
வெறுமை
set_utmpx_time(கட்டமைப்பு logininfo *li, கட்டமைப்பு utmpx *utx)
{
# எனில் defined(HAVE_TV_IN_UTMPX)
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMPX)
	utx->ut_time = li->tv_sec;
# endif
}

வெறுமை
construct_utmpx(கட்டமைப்பு logininfo *li, கட்டமைப்பு utmpx *utx)
{
# ifdef HAVE_ADDR_V6_IN_UTMPX
	கட்டமைப்பு sockaddr_in6 *sa6;
#  endif
	memset(utx, '\0', அளவு(*utx));

# ifdef HAVE_ID_IN_UTMPX
	வரி_abbrevname(utx->ut_id, li->வரி, அளவு(utx->ut_id));
# endif

	/* this is done here to keep utmp constants out of loginrec.h */
	தேர்வு (li->type) {
	நிலை LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		நிறுத்து;
	நிலை LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		நிறுத்து;
	}
	வரி_stripname(utx->ut_வரி, li->வரி, அளவு(utx->ut_வரி));
	set_utmpx_time(li, utx);
	utx->ut_pid = li->pid;

	/* strncpy(): Don't necessarily want null termination */
	strncpy(utx->ut_user, li->username,
	    MIN_SIZEOF(utx->ut_user, li->username));

	எனில் (li->type == LTYPE_LOGOUT)
		திரும்பு;

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
	எனில் (li->hostaddr.sa.sa_family == AF_INET)
		utx->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMPX
	/* this is just a 128-bit IPv6 address */
	எனில் (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((கட்டமைப்பு sockaddr_in6 *)&li->hostaddr.sa);
		memcpy(utx->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		எனில் (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			utx->ut_addr_v6[0] = utx->ut_addr_v6[3];
			utx->ut_addr_v6[1] = 0;
			utx->ut_addr_v6[2] = 0;
			utx->ut_addr_v6[3] = 0;
		}
	}
# endif
# ifdef HAVE_SYSLEN_IN_UTMPX
	/* ut_syslen is the length of the utx_host string */
	utx->ut_syslen = MINIMUM(strlen(li->hostname), அளவு(utx->ut_host));
# endif
}
#endif /* USE_UTMPX || USE_WTMPX */

/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */
#ifdef USE_UTMP

/* if we can, use pututline() etc. */
# எனில் !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
	defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
# endif


/* write a utmp entry with the system's help (pututline() and pals) */
# ifdef UTMP_USE_LIBRARY
நிலையான முழு
utmp_write_library(கட்டமைப்பு logininfo *li, கட்டமைப்பு utmp *ut)
{
	setutent();
	pututline(ut);
#  ifdef HAVE_ENDUTENT
	endutent();
#  endif
	திரும்பு (1);
}
# இல்லையெனில் /* UTMP_USE_LIBRARY */

/*
 * Write a utmp entry direct to the file
 * This is a slightly modification of code in OpenBSD's login.c
 */
நிலையான முழு
utmp_write_direct(கட்டமைப்பு logininfo *li, கட்டமைப்பு utmp *ut)
{
	கட்டமைப்பு utmp old_ut;
	பதிவு முழு fd;
	முழு tty;

	/* FIXME: (ATL) ttyslot() needs local implementation */

#எனில் defined(HAVE_GETTTYENT)
	கட்டமைப்பு ttyent *ty;

	tty=0;
	setttyent();
	போது (வெற்று != (ty = getttyent())) {
		tty++;
		எனில் (!strncmp(ty->ty_name, ut->ut_வரி, அளவு(ut->ut_வரி)))
			நிறுத்து;
	}
	endttyent();

	எனில் (வெற்று == ty) {
		logit_f("tty not found");
		திரும்பு (0);
	}
#இல்லையெனில் /* FIXME */

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

#endif /* HAVE_GETTTYENT */

	எனில் (tty > 0 && (fd = open(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		off_t pos, ret;

		pos = (off_t)tty * அளவு(கட்டமைப்பு utmp);
		எனில் ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			திரும்பு (0);
		}
		எனில் (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			திரும்பு (0);
		}
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		எனில் (atomicio(பட, fd, &old_ut, அளவு(old_ut)) == அளவு(old_ut) &&
		    (ut->ut_host[0] == '\0') && (old_ut.ut_host[0] != '\0') &&
		    (strncmp(old_ut.ut_வரி, ut->ut_வரி, அளவு(ut->ut_வரி)) == 0) &&
		    (strncmp(old_ut.ut_name, ut->ut_name, அளவு(ut->ut_name)) == 0))
			memcpy(ut->ut_host, old_ut.ut_host, அளவு(ut->ut_host));

		எனில் ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			திரும்பு (0);
		}
		எனில் (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			திரும்பு (0);
		}
		எனில் (atomicio(vwrite, fd, ut, அளவு(*ut)) != அளவு(*ut)) {
			logit("%s: error writing %s: %s", __func__,
			    UTMP_FILE, strerror(errno));
			close(fd);
			திரும்பு (0);
		}

		close(fd);
		திரும்பு (1);
	} இல்லையெனில் {
		திரும்பு (0);
	}
}
# endif /* UTMP_USE_LIBRARY */

நிலையான முழு
utmp_perform_login(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	எனில் (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		திரும்பு (0);
	}
# இல்லையெனில்
	எனில் (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		திரும்பு (0);
	}
# endif
	திரும்பு (1);
}


நிலையான முழு
utmp_perform_logout(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	எனில் (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		திரும்பு (0);
	}
# இல்லையெனில்
	எனில் (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		திரும்பு (0);
	}
# endif
	திரும்பு (1);
}


முழு
utmp_write_entry(கட்டமைப்பு logininfo *li)
{
	தேர்வு(li->type) {
	நிலை LTYPE_LOGIN:
		திரும்பு (utmp_perform_login(li));

	நிலை LTYPE_LOGOUT:
		திரும்பு (utmp_perform_logout(li));

	இயல்பு:
		logit_f("invalid type field");
		திரும்பு (0);
	}
}
#endif /* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#ifdef USE_UTMPX

/* if we have the wherewithal, use pututxline etc. */
# எனில் !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) && \
	defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
# endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
# ifdef UTMPX_USE_LIBRARY
நிலையான முழு
utmpx_write_library(கட்டமைப்பு logininfo *li, கட்டமைப்பு utmpx *utx)
{
	setutxent();
	pututxline(utx);

#  ifdef HAVE_ENDUTXENT
	endutxent();
#  endif
	திரும்பு (1);
}

# இல்லையெனில் /* UTMPX_USE_LIBRARY */

/* write a utmp entry direct to the file */
நிலையான முழு
utmpx_write_direct(கட்டமைப்பு logininfo *li, கட்டமைப்பு utmpx *utx)
{
	logit_f("not implemented!");
	திரும்பு (0);
}
# endif /* UTMPX_USE_LIBRARY */

நிலையான முழு
utmpx_perform_login(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு utmpx utx;

	construct_utmpx(li, &utx);
# ifdef UTMPX_USE_LIBRARY
	எனில் (!utmpx_write_library(li, &utx)) {
		logit_f("utmp_write_library() failed");
		திரும்பு (0);
	}
# இல்லையெனில்
	எனில் (!utmpx_write_direct(li, &utx)) {
		logit_f("utmp_write_direct() failed");
		திரும்பு (0);
	}
# endif
	திரும்பு (1);
}


நிலையான முழு
utmpx_perform_logout(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு utmpx utx;

	construct_utmpx(li, &utx);
# ifdef HAVE_ID_IN_UTMPX
	வரி_abbrevname(utx.ut_id, li->வரி, அளவு(utx.ut_id));
# endif
# ifdef HAVE_TYPE_IN_UTMPX
	utx.ut_type = DEAD_PROCESS;
# endif

# ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
# இல்லையெனில்
	utmpx_write_direct(li, &utx);
# endif
	திரும்பு (1);
}

முழு
utmpx_write_entry(கட்டமைப்பு logininfo *li)
{
	தேர்வு(li->type) {
	நிலை LTYPE_LOGIN:
		திரும்பு (utmpx_perform_login(li));
	நிலை LTYPE_LOGOUT:
		திரும்பு (utmpx_perform_logout(li));
	இயல்பு:
		logit_f("invalid type field");
		திரும்பு (0);
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
நிலையான முழு
wtmp_write(கட்டமைப்பு logininfo *li, கட்டமைப்பு utmp *ut)
{
	கட்டமைப்பு stat buf;
	முழு fd, ret = 1;

	எனில் ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem writing %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		திரும்பு (0);
	}
	எனில் (fstat(fd, &buf) == 0)
		எனில் (atomicio(vwrite, fd, ut, அளவு(*ut)) != அளவு(*ut)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMP_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);
	திரும்பு (ret);
}

நிலையான முழு
wtmp_perform_login(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு utmp ut;

	construct_utmp(li, &ut);
	திரும்பு (wtmp_write(li, &ut));
}


நிலையான முழு
wtmp_perform_logout(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு utmp ut;

	construct_utmp(li, &ut);
	திரும்பு (wtmp_write(li, &ut));
}


முழு
wtmp_write_entry(கட்டமைப்பு logininfo *li)
{
	தேர்வு(li->type) {
	நிலை LTYPE_LOGIN:
		திரும்பு (wtmp_perform_login(li));
	நிலை LTYPE_LOGOUT:
		திரும்பு (wtmp_perform_logout(li));
	இயல்பு:
		logit_f("invalid type field");
		திரும்பு (0);
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
நிலையான முழு
wtmp_islogin(கட்டமைப்பு logininfo *li, கட்டமைப்பு utmp *ut)
{
	எனில் (strncmp(li->username, ut->ut_name,
	    MIN_SIZEOF(li->username, ut->ut_name)) == 0) {
# ifdef HAVE_TYPE_IN_UTMP
		எனில் (ut->ut_type & USER_PROCESS)
			திரும்பு (1);
# இல்லையெனில்
		திரும்பு (1);
# endif
	}
	திரும்பு (0);
}

முழு
wtmp_get_entry(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு stat st;
	கட்டமைப்பு utmp ut;
	முழு fd, found = 0;

	/* Clear the time entries in our logininfo */
	li->tv_sec = li->tv_usec = 0;

	எனில் ((fd = open(WTMP_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		திரும்பு (0);
	}
	எனில் (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		close(fd);
		திரும்பு (0);
	}

	/* Seek to the start of the last struct utmp */
	எனில் (lseek(fd, -(off_t)அளவு(கட்டமைப்பு utmp), SEEK_END) == -1) {
		/* Looks like we've got a fresh wtmp file */
		close(fd);
		திரும்பு (0);
	}

	போது (!found) {
		எனில் (atomicio(பட, fd, &ut, அளவு(ut)) != அளவு(ut)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMP_FILE, strerror(errno));
			close (fd);
			திரும்பு (0);
		}
		எனில் (wtmp_islogin(li, &ut) ) {
			found = 1;
			/*
			 * We've already checked for a time in struct
			 * utmp, in login_getlast()
			 */
# ifdef HAVE_TIME_IN_UTMP
			li->tv_sec = ut.ut_time;
# இல்லையெனில்
#  எனில் HAVE_TV_IN_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
# endif
			வரி_fullname(li->வரி, ut.ut_வரி,
			    MIN_SIZEOF(li->வரி, ut.ut_வரி));
# ifdef HAVE_HOST_IN_UTMP
			strlcpy(li->hostname, ut.ut_host,
			    MIN_SIZEOF(li->hostname, ut.ut_host));
# endif
			தொடர்;
		}
		/* Seek back 2 x struct utmp */
		எனில் (lseek(fd, -(off_t)(2 * அளவு(கட்டமைப்பு utmp)), SEEK_CUR) == -1) {
			/* We've found the start of the file, so quit */
			close(fd);
			திரும்பு (0);
		}
	}

	/* We found an entry. Tidy up and return */
	close(fd);
	திரும்பு (1);
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
நிலையான முழு
wtmpx_write(கட்டமைப்பு logininfo *li, கட்டமைப்பு utmpx *utx)
{
#ifndef HAVE_UPDWTMPX
	கட்டமைப்பு stat buf;
	முழு fd, ret = 1;

	எனில் ((fd = open(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		திரும்பு (0);
	}

	எனில் (fstat(fd, &buf) == 0)
		எனில் (atomicio(vwrite, fd, utx, அளவு(*utx)) != அளவு(*utx)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);

	திரும்பு (ret);
#இல்லையெனில்
	updwtmpx(WTMPX_FILE, utx);
	திரும்பு (1);
#endif
}


நிலையான முழு
wtmpx_perform_login(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு utmpx utx;

	construct_utmpx(li, &utx);
	திரும்பு (wtmpx_write(li, &utx));
}


நிலையான முழு
wtmpx_perform_logout(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு utmpx utx;

	construct_utmpx(li, &utx);
	திரும்பு (wtmpx_write(li, &utx));
}


முழு
wtmpx_write_entry(கட்டமைப்பு logininfo *li)
{
	தேர்வு(li->type) {
	நிலை LTYPE_LOGIN:
		திரும்பு (wtmpx_perform_login(li));
	நிலை LTYPE_LOGOUT:
		திரும்பு (wtmpx_perform_logout(li));
	இயல்பு:
		logit_f("invalid type field");
		திரும்பு (0);
	}
}

/* Please see the notes above wtmp_islogin() for information about the
   next two functions */

/* Return true if this wtmpx entry indicates a login */
நிலையான முழு
wtmpx_islogin(கட்டமைப்பு logininfo *li, கட்டமைப்பு utmpx *utx)
{
	எனில் (strncmp(li->username, utx->ut_user,
	    MIN_SIZEOF(li->username, utx->ut_user)) == 0 ) {
# ifdef HAVE_TYPE_IN_UTMPX
		எனில் (utx->ut_type == USER_PROCESS)
			திரும்பு (1);
# இல்லையெனில்
		திரும்பு (1);
# endif
	}
	திரும்பு (0);
}


முழு
wtmpx_get_entry(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு stat st;
	கட்டமைப்பு utmpx utx;
	முழு fd, found=0;

	/* Clear the time entries */
	li->tv_sec = li->tv_usec = 0;

	எனில் ((fd = open(WTMPX_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		திரும்பு (0);
	}
	எனில் (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		close(fd);
		திரும்பு (0);
	}

	/* Seek to the start of the last struct utmpx */
	எனில் (lseek(fd, -(off_t)அளவு(கட்டமைப்பு utmpx), SEEK_END) == -1 ) {
		/* probably a newly rotated wtmpx file */
		close(fd);
		திரும்பு (0);
	}

	போது (!found) {
		எனில் (atomicio(பட, fd, &utx, அளவு(utx)) != அளவு(utx)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			close (fd);
			திரும்பு (0);
		}
		/*
		 * Logouts are recorded as a blank username on a particular
		 * line. So, we just need to find the username in struct utmpx
		 */
		எனில் (wtmpx_islogin(li, &utx)) {
			found = 1;
# எனில் defined(HAVE_TV_IN_UTMPX)
			li->tv_sec = utx.ut_tv.tv_sec;
# elif defined(HAVE_TIME_IN_UTMPX)
			li->tv_sec = utx.ut_time;
# endif
			வரி_fullname(li->வரி, utx.ut_வரி, அளவு(li->வரி));
# எனில் defined(HAVE_HOST_IN_UTMPX)
			strlcpy(li->hostname, utx.ut_host,
			    MIN_SIZEOF(li->hostname, utx.ut_host));
# endif
			தொடர்;
		}
		எனில் (lseek(fd, -(off_t)(2 * அளவு(கட்டமைப்பு utmpx)), SEEK_CUR) == -1) {
			close(fd);
			திரும்பு (0);
		}
	}

	close(fd);
	திரும்பு (1);
}
#endif /* USE_WTMPX */

#ifdef USE_WTMPDB
நிலையான முழு
wtmpdb_perform_login(கட்டமைப்பு logininfo *li)
{
	uint64_t login_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	    li->tv_usec;
	மாறிலி எழுத்து *tty;

	எனில் (strncmp(li->வரி, "/dev/", 5) == 0)
		tty = &(li->வரி[5]);
	இல்லையெனில்
		tty = li->வரி;

	li->wtmpdb_id = wtmpdb_login(வெற்று, USER_PROCESS, li->username,
	    login_time, tty, li->hostname, 0, 0);

	எனில் (li->wtmpdb_id < 0)
		திரும்பு (0);

	திரும்பு (1);
}

நிலையான முழு
wtmpdb_perform_logout(கட்டமைப்பு logininfo *li)
{
	uint64_t logout_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	   li->tv_usec;

	எனில் (li->wtmpdb_id == 0) {
		மாறிலி எழுத்து *tty;

		எனில் (strncmp(li->வரி, "/dev/", 5) == 0)
			tty = &(li->வரி[5]);
		இல்லையெனில்
			tty = li->வரி;

		li->wtmpdb_id = wtmpdb_get_id(வெற்று, tty, வெற்று);
	}
	wtmpdb_logout(வெற்று, li->wtmpdb_id, logout_time, வெற்று);

	திரும்பு (1);
}

முழு
wtmpdb_write_entry(கட்டமைப்பு logininfo *li)
{
	தேர்வு(li->type) {
	நிலை LTYPE_LOGIN:
		திரும்பு (wtmpdb_perform_login(li));
	நிலை LTYPE_LOGOUT:
		திரும்பு (wtmpdb_perform_logout(li));
	இயல்பு:
		logit_f("invalid type field");
		திரும்பு (0);
	}
}
#endif

/**
 ** Low-level libutil login() functions
 **/

#ifdef USE_LOGIN
நிலையான முழு
syslogin_perform_login(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு utmp *ut;

	ut = xmalloc(அளவு(*ut));
	construct_utmp(li, ut);
	login(ut);
	விடுவி(ut);

	திரும்பு (1);
}

நிலையான முழு
syslogin_perform_logout(கட்டமைப்பு logininfo *li)
{
# ifdef HAVE_LOGOUT
	எழுத்து வரி[UT_LINESIZE];

	(வெறுமை)வரி_stripname(வரி, li->வரி, அளவு(வரி));

	எனில் (!logout(வரி))
		logit_f("logout() returned an error");
#  ifdef HAVE_LOGWTMP
	இல்லையெனில்
		logwtmp(வரி, "", "");
#  endif
	/* FIXME: (ATL - if the need arises) What to do if we have
	 * login, but no logout?  what if logout but no logwtmp? All
	 * routines are in libutil so they should all be there,
	 * but... */
# endif
	திரும்பு (1);
}

முழு
syslogin_write_entry(கட்டமைப்பு logininfo *li)
{
	தேர்வு (li->type) {
	நிலை LTYPE_LOGIN:
		திரும்பு (syslogin_perform_login(li));
	நிலை LTYPE_LOGOUT:
		திரும்பு (syslogin_perform_logout(li));
	இயல்பு:
		logit_f("Invalid type field");
		திரும்பு (0);
	}
}
#endif /* USE_LOGIN */

/* end of file log-syslogin.c */

/**
 ** Low-level lastlog functions
 **/

#ifdef USE_LASTLOG

#எனில் !defined(LASTLOG_WRITE_PUTUTXLINE) || !defined(HAVE_GETLASTLOGXBYNAME)
/* open the file (using filemode) and seek to the login entry */
நிலையான முழு
lastlog_openseek(கட்டமைப்பு logininfo *li, முழு *fd, முழு filemode)
{
	off_t offset;
	எழுத்து lastlog_file[1024];
	கட்டமைப்பு stat st;

	எனில் (stat(LASTLOG_FILE, &st) != 0) {
		logit("%s: Couldn't stat %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		திரும்பு (0);
	}
	எனில் (S_ISDIR(st.st_mode)) {
		snprintf(lastlog_file, அளவு(lastlog_file), "%s/%s",
		    LASTLOG_FILE, li->username);
	} இல்லையெனில் எனில் (S_ISREG(st.st_mode)) {
		strlcpy(lastlog_file, LASTLOG_FILE, அளவு(lastlog_file));
	} இல்லையெனில் {
		logit("%s: %.100s is not a file or directory!", __func__,
		    LASTLOG_FILE);
		திரும்பு (0);
	}

	*fd = open(lastlog_file, filemode, 0600);
	எனில் (*fd < 0) {
		debug("%s: Couldn't open %s: %s", __func__,
		    lastlog_file, strerror(errno));
		திரும்பு (0);
	}

	எனில் (S_ISREG(st.st_mode)) {
		/* find this uid's offset in the lastlog file */
		offset = (off_t) ((u_long)li->uid * அளவு(கட்டமைப்பு lastlog));

		எனில் (lseek(*fd, offset, SEEK_SET) != offset) {
			logit("%s: %s->lseek(): %s", __func__,
			    lastlog_file, strerror(errno));
			close(*fd);
			திரும்பு (0);
		}
	}

	திரும்பு (1);
}
#endif /* !LASTLOG_WRITE_PUTUTXLINE || !HAVE_GETLASTLOGXBYNAME */

#ifdef LASTLOG_WRITE_PUTUTXLINE
முழு
lastlog_write_entry(கட்டமைப்பு logininfo *li)
{
	தேர்வு(li->type) {
	நிலை LTYPE_LOGIN:
		திரும்பு 1; /* lastlog written by pututxline */
	இயல்பு:
		logit("lastlog_write_entry: Invalid type field");
		திரும்பு 0;
	}
}
#இல்லையெனில் /* LASTLOG_WRITE_PUTUTXLINE */
முழு
lastlog_write_entry(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு lastlog last;
	முழு fd;

	தேர்வு(li->type) {
	நிலை LTYPE_LOGIN:
		/* create our struct lastlog */
		memset(&last, '\0', அளவு(last));
		வரி_stripname(last.ll_வரி, li->வரி, அளவு(last.ll_வரி));
		strlcpy(last.ll_host, li->hostname,
		    MIN_SIZEOF(last.ll_host, li->hostname));
		last.ll_time = li->tv_sec;

		எனில் (!lastlog_openseek(li, &fd, O_RDWR|O_CREAT))
			திரும்பு (0);

		/* write the entry */
		எனில் (atomicio(vwrite, fd, &last, அளவு(last)) != அளவு(last)) {
			close(fd);
			logit("%s: Error writing to %s: %s", __func__,
			    LASTLOG_FILE, strerror(errno));
			திரும்பு (0);
		}

		close(fd);
		திரும்பு (1);
	இயல்பு:
		logit_f("Invalid type field");
		திரும்பு (0);
	}
}
#endif /* LASTLOG_WRITE_PUTUTXLINE */

#ifdef HAVE_GETLASTLOGXBYNAME
முழு
lastlog_get_entry(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு lastlogx l, *ll;

	எனில் ((ll = getlastlogxbyname(li->username, &l)) == வெற்று) {
		memset(&l, '\0', அளவு(l));
		ll = &l;
	}
	வரி_fullname(li->வரி, ll->ll_வரி, அளவு(li->வரி));
	strlcpy(li->hostname, ll->ll_host,
		MIN_SIZEOF(li->hostname, ll->ll_host));
	li->tv_sec = ll->ll_tv.tv_sec;
	li->tv_usec = ll->ll_tv.tv_usec;
	திரும்பு (1);
}
#இல்லையெனில் /* HAVE_GETLASTLOGXBYNAME */
முழு
lastlog_get_entry(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு lastlog last;
	முழு fd, ret;

	எனில் (!lastlog_openseek(li, &fd, O_RDONLY))
		திரும்பு (0);

	ret = atomicio(பட, fd, &last, அளவு(last));
	close(fd);

	தேர்வு (ret) {
	நிலை 0:
		memset(&last, '\0', அளவு(last));
		/* FALLTHRU */
	நிலை அளவு(last):
		வரி_fullname(li->வரி, last.ll_வரி, அளவு(li->வரி));
		strlcpy(li->hostname, last.ll_host,
		    MIN_SIZEOF(li->hostname, last.ll_host));
		li->tv_sec = last.ll_time;
		திரும்பு (1);
	நிலை -1:
		error("%s: Error reading from %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		திரும்பு (0);
	இயல்பு:
		error("%s: Error reading from %s: Expecting %d, got %d",
		    __func__, LASTLOG_FILE, (முழு)அளவு(last), ret);
		திரும்பு (0);
	}

	/* NOTREACHED */
	திரும்பு (0);
}
#endif /* HAVE_GETLASTLOGXBYNAME */
#endif /* USE_LASTLOG */

#எனில் defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
முழு
utmpx_get_entry(கட்டமைப்பு logininfo *li)
{
	கட்டமைப்பு utmpx *utx;

	எனில் (setutxdb(UTXDB_LASTLOGIN, வெற்று) != 0)
		திரும்பு (0);
	utx = getutxuser(li->username);
	எனில் (utx == வெற்று) {
		endutxent();
		திரும்பு (0);
	}

	வரி_fullname(li->வரி, utx->ut_வரி,
	    MIN_SIZEOF(li->வரி, utx->ut_வரி));
	strlcpy(li->hostname, utx->ut_host,
	    MIN_SIZEOF(li->hostname, utx->ut_host));
	li->tv_sec = utx->ut_tv.tv_sec;
	li->tv_usec = utx->ut_tv.tv_usec;
	endutxent();
	திரும்பு (1);
}
#endif /* USE_UTMPX && HAVE_SETUTXDB && UTXDB_LASTLOGIN && HAVE_GETUTXUSER */

#ifdef USE_BTMP
/*
 * Logs failed login attempts in _PATH_BTMP if that exists.
 * The most common login failure is to give password instead of username.
 * So the _PATH_BTMP file is checked for the correct permission, so that only
 * root can read it.
 */
வெறுமை
record_failed_login(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *username, மாறிலி எழுத்து *hostname,
    மாறிலி எழுத்து *ttyn)
{
	முழு fd;
	கட்டமைப்பு utmp ut;
	கட்டமைப்பு logininfo li;
	socklen_t fromlen = அளவு(li.hostaddr);
	time_t t;
	கட்டமைப்பு stat fst;

	எனில் (geteuid() != 0)
		திரும்பு;
	எனில் ((fd = open(_PATH_BTMP, O_WRONLY | O_APPEND)) < 0) {
		debug("Unable to open the btmp file %s: %s", _PATH_BTMP,
		    strerror(errno));
		திரும்பு;
	}
	எனில் (fstat(fd, &fst) < 0) {
		logit("%s: fstat of %s failed: %s", __func__, _PATH_BTMP,
		    strerror(errno));
		செல் out;
	}
	எனில் ((fst.st_mode & (S_IXGRP | S_IRWXO)) || fst.st_uid != 0) {
		logit("Excess permission or bad ownership on file %s",
		    _PATH_BTMP);
		செல் out;
	}

	/* Construct a logininfo and turn it into a utmp */
	memset(&li, 0, அளவு(li));
	li.type = LTYPE_FAILED;
	li.pid = getpid();
	strlcpy(li.வரி, "ssh:notty", அளவு(li.வரி));
	strlcpy(li.username, username, அளவு(li.username));
	strlcpy(li.hostname, hostname, அளவு(li.hostname));
	time(&t);
	li.tv_sec = t > 0 ? (unsigned long)t : 0;
	எனில் (ssh_packet_connection_is_on_socket(ssh)) {
		(வெறுமை)getpeername(ssh_packet_get_connection_in(ssh),
		    &li.hostaddr.sa, &fromlen);
	}
	construct_utmp(&li, &ut);

	எனில் (atomicio(vwrite, fd, &ut, அளவு(ut)) != அளவு(ut)) {
		error("Failed to write to %s: %s", _PATH_BTMP,
		    strerror(errno));
	}
out:
	close(fd);
}
#endif	/* USE_BTMP */
