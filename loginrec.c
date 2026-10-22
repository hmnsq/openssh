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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/time.h>

#অন্তর্ভাব <netinet/in.h>

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "loginrec.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "atomicio.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "misc.h"

# include <util.h>

#ifdef USE_WTMPDB
# include <wtmpdb.h>
#endif

/**
 ** prototypes for helper functions in this file
 **/

#যদি HAVE_UTMP_H
শূন্য set_utmp_time(সংরচনা logininfo *li, সংরচনা utmp *ut);
শূন্য construct_utmp(সংরচনা logininfo *li, সংরচনা utmp *ut);
#endif

#ifdef HAVE_UTMPX_H
শূন্য set_utmpx_time(সংরচনা logininfo *li, সংরচনা utmpx *ut);
শূন্য construct_utmpx(সংরচনা logininfo *li, সংরচনা utmpx *ut);
#endif

পূর্ণাঙ্ক utmp_write_entry(সংরচনা logininfo *li);
পূর্ণাঙ্ক utmpx_write_entry(সংরচনা logininfo *li);
পূর্ণাঙ্ক wtmp_write_entry(সংরচনা logininfo *li);
পূর্ণাঙ্ক wtmpx_write_entry(সংরচনা logininfo *li);
পূর্ণাঙ্ক lastlog_write_entry(সংরচনা logininfo *li);
পূর্ণাঙ্ক syslogin_write_entry(সংরচনা logininfo *li);
#ifdef USE_WTMPDB
পূর্ণাঙ্ক wtmpdb_write_entry(সংরচনা logininfo *li);
#endif

পূর্ণাঙ্ক getlast_entry(সংরচনা logininfo *li);
পূর্ণাঙ্ক lastlog_get_entry(সংরচনা logininfo *li);
পূর্ণাঙ্ক utmpx_get_entry(সংরচনা logininfo *li);
পূর্ণাঙ্ক wtmp_get_entry(সংরচনা logininfo *li);
পূর্ণাঙ্ক wtmpx_get_entry(সংরচনা logininfo *li);

বাহ্য সংরচনা sshbuf *loginmsg;

/* pick the shortest string */
#define MIN_SIZEOF(s1,s2) (পরিমাণ(s1) < পরিমাণ(s2) ? পরিমাণ(s1) : পরিমাণ(s2))

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
পূর্ণাঙ্ক
login_login(সংরচনা logininfo *li)
{
	li->type = LTYPE_LOGIN;
	প্রত্যাগম (login_write(li));
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
পূর্ণাঙ্ক
login_logout(সংরচনা logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	প্রত্যাগম (login_write(li));
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
unsigned পূর্ণাঙ্ক
login_get_lastlog_time(ধ্রুব uid_t uid)
{
	সংরচনা logininfo li;

	যদি (login_get_lastlog(&li, uid))
		প্রত্যাগম (li.tv_sec);
	অন্যথা
		প্রত্যাগম (0);
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
সংরচনা logininfo *
login_get_lastlog(সংরচনা logininfo *li, ধ্রুব uid_t uid)
{
	সংরচনা passwd *pw;

	memset(li, '\0', পরিমাণ(*li));
	li->uid = uid;

	/*
	 * If we don't have a 'real' lastlog, we need the username to
	 * reliably search wtmp(x) for the last login (see
	 * wtmp_get_entry().)
	 */
	pw = getpwuid(uid);
	যদি (pw == রিক্ত)
		fatal("%s: Cannot find account for uid %ld", __func__,
		    (long)uid);

	যদি (strlcpy(li->username, pw->pw_name, পরিমাণ(li->username)) >=
	    পরিমাণ(li->username)) {
		error("%s: username too long (%lu > max %lu)", __func__,
		    (unsigned long)strlen(pw->pw_name),
		    (unsigned long)পরিমাণ(li->username) - 1);
		প্রত্যাগম রিক্ত;
	}

	যদি (getlast_entry(li))
		প্রত্যাগম (li);
	অন্যথা
		প্রত্যাগম (রিক্ত);
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
সংরচনা
logininfo *login_alloc_entry(pid_t pid, ধ্রুব বর্ণ *username,
    ধ্রুব বর্ণ *hostname, ধ্রুব বর্ণ *সারি)
{
	সংরচনা logininfo *newli;

	newli = xmalloc(পরিমাণ(*newli));
	login_init_entry(newli, pid, username, hostname, সারি);
	প্রত্যাগম (newli);
}


/* login_free_entry(struct logininfo *)    - free struct memory */
শূন্য
login_free_entry(সংরচনা logininfo *li)
{
	মুক্ত(li);
}


/* login_init_entry(struct logininfo *, int, char*, char*, char*)
 *                                        - initialise a struct logininfo
 *
 * Populates a new struct logininfo, a data structure meant to carry
 * the information required to portably record login info.
 *
 * Returns: 1
 */
পূর্ণাঙ্ক
login_init_entry(সংরচনা logininfo *li, pid_t pid, ধ্রুব বর্ণ *username,
    ধ্রুব বর্ণ *hostname, ধ্রুব বর্ণ *সারি)
{
	সংরচনা passwd *pw;

	memset(li, 0, পরিমাণ(*li));

	li->pid = pid;

	/* set the line information */
	যদি (সারি)
		সারি_fullname(li->সারি, সারি, পরিমাণ(li->সারি));

	যদি (username) {
		strlcpy(li->username, username, পরিমাণ(li->username));
		pw = getpwnam(li->username);
		যদি (pw == রিক্ত) {
			fatal("%s: Cannot find user \"%s\"", __func__,
			    li->username);
		}
		li->uid = pw->pw_uid;
	}

	যদি (hostname)
		strlcpy(li->hostname, hostname, পরিমাণ(li->hostname));

	প্রত্যাগম (1);
}

/*
 * login_set_current_time(struct logininfo *)    - set the current time
 *
 * Set the current time in a logininfo structure. This function is
 * meant to eliminate the need to deal with system dependencies for
 * time handling.
 */
শূন্য
login_set_current_time(সংরচনা logininfo *li)
{
	সংরচনা timeval tv;

	gettimeofday(&tv, রিক্ত);

	li->tv_sec = tv.tv_sec;
	li->tv_usec = tv.tv_usec;
}

/* copy a sockaddr_* into our logininfo */
শূন্য
login_set_addr(সংরচনা logininfo *li, ধ্রুব সংরচনা sockaddr *sa,
    ধ্রুব unsigned পূর্ণাঙ্ক sa_size)
{
	unsigned পূর্ণাঙ্ক bufsize = sa_size;

	/* make sure we don't overrun our union */
	যদি (পরিমাণ(li->hostaddr) < sa_size)
		bufsize = পরিমাণ(li->hostaddr);

	memcpy(&li->hostaddr.sa, sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/
পূর্ণাঙ্ক
login_write(সংরচনা logininfo *li)
{
#ifndef HAVE_CYGWIN
	যদি (geteuid() != 0) {
		logit("Attempt to write login records by non-root user (aborting)");
		প্রত্যাগম (1);
	}
#endif

	/* set the timestamp */
	login_set_current_time(li);
#ifdef USE_LOGIN
	syslogin_write_entry(li);
#endif
#ifdef USE_LASTLOG
	যদি (li->type == LTYPE_LOGIN)
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
	যদি (li->type == LTYPE_LOGIN &&
	    !sys_auth_record_login(li->username,li->hostname,li->সারি,
	    loginmsg))
		logit("Writing login record failed for %s", li->username);
#endif
#ifdef SSH_AUDIT_EVENTS
	যদি (li->type == LTYPE_LOGIN)
		audit_session_open(li);
	অন্যথা যদি (li->type == LTYPE_LOGOUT)
		audit_session_close(li);
#endif
	প্রত্যাগম (0);
}

#ifdef LOGIN_NEEDS_UTMPX
পূর্ণাঙ্ক
login_utmp_only(সংরচনা logininfo *li)
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
	প্রত্যাগম (0);
}
#endif

/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
পূর্ণাঙ্ক
getlast_entry(সংরচনা logininfo *li)
{
#ifdef USE_LASTLOG
	প্রত্যাগম(lastlog_get_entry(li));
#অন্যথা /* !USE_LASTLOG */
#যদি defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
	প্রত্যাগম (utmpx_get_entry(li));
#endif

#যদি defined(DISABLE_LASTLOG)
	/* On some systems we shouldn't even try to obtain last login
	 * time, e.g. AIX */
	প্রত্যাগম (0);
# elif defined(USE_WTMP) && \
    (defined(HAVE_TIME_IN_UTMP) || defined(HAVE_TV_IN_UTMP))
	/* retrieve last login time from utmp */
	প্রত্যাগম (wtmp_get_entry(li));
# elif defined(USE_WTMPX) && \
    (defined(HAVE_TIME_IN_UTMPX) || defined(HAVE_TV_IN_UTMPX))
	/* If wtmp isn't available, try wtmpx */
	প্রত্যাগম (wtmpx_get_entry(li));
# অন্যথা
	/* Give up: No means of retrieving last login time */
	প্রত্যাগম (0);
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
বর্ণ *
সারি_fullname(বর্ণ *dst, ধ্রুব বর্ণ *src, u_int dstsize)
{
	memset(dst, '\0', dstsize);
	যদি ((strncmp(src, "/dev/", 5) == 0) || (dstsize < (strlen(src) + 5)))
		strlcpy(dst, src, dstsize);
	অন্যথা {
		strlcpy(dst, "/dev/", dstsize);
		strlcat(dst, src, dstsize);
	}
	প্রত্যাগম (dst);
}

/* line_stripname(): strip the leading '/dev' if it exists, return dst */
বর্ণ *
সারি_stripname(বর্ণ *dst, ধ্রুব বর্ণ *src, পূর্ণাঙ্ক dstsize)
{
	memset(dst, '\0', dstsize);
	যদি (strncmp(src, "/dev/", 5) == 0)
		strlcpy(dst, src + 5, dstsize);
	অন্যথা
		strlcpy(dst, src, dstsize);
	প্রত্যাগম (dst);
}

/*
 * line_abbrevname(): Return the abbreviated (usually four-character)
 * form of the line (Just use the last <dstsize> characters of the
 * full name.)
 *
 * NOTE: use strncpy because we do NOT necessarily want zero
 * termination
 */
বর্ণ *
সারি_abbrevname(বর্ণ *dst, ধ্রুব বর্ণ *src, পূর্ণাঙ্ক dstsize)
{
	size_t len;

	memset(dst, '\0', dstsize);

	যদি (strcmp(src, "ssh:notty") == 0)
		প্রত্যাগম dst;

	/* Always skip prefix if present */
	যদি (strncmp(src, "/dev/", 5) == 0)
		src += 5;

#ifdef WITH_ABBREV_NO_TTY
	যদি (strncmp(src, "tty", 3) == 0)
		src += 3;
#endif

	len = strlen(src);

	যদি (len > 0) {
		যদি (((পূর্ণাঙ্ক)len - dstsize) > 0)
			src +=  ((পূর্ণাঙ্ক)len - dstsize);

		/* note: _don't_ change this to strlcpy */
		strncpy(dst, src, (size_t)dstsize);
	}

	প্রত্যাগম (dst);
}

/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#যদি defined(USE_BTMP) || defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
শূন্য
set_utmp_time(সংরচনা logininfo *li, সংরচনা utmp *ut)
{
# যদি defined(HAVE_TV_IN_UTMP)
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMP)
	ut->ut_time = li->tv_sec;
# endif
}

শূন্য
construct_utmp(সংরচনা logininfo *li,
		    সংরচনা utmp *ut)
{
# ifdef HAVE_ADDR_V6_IN_UTMP
	সংরচনা sockaddr_in6 *sa6;
# endif

	memset(ut, '\0', পরিমাণ(*ut));

	/* First fill out fields used for both logins and logouts */

# ifdef HAVE_ID_IN_UTMP
	সারি_abbrevname(ut->ut_id, li->সারি, পরিমাণ(ut->ut_id));
# endif

# ifdef HAVE_TYPE_IN_UTMP
	/* This is done here to keep utmp constants out of struct logininfo */
	বিকল্প (li->type) {
	পক্ষ LTYPE_FAILED:
		ut->ut_type = LOGIN_PROCESS;
		ভঙ্গ;
	পক্ষ LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		ভঙ্গ;
	পক্ষ LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		ভঙ্গ;
	}
# endif
	set_utmp_time(li, ut);

	সারি_stripname(ut->ut_সারি, li->সারি, পরিমাণ(ut->ut_সারি));

# ifdef HAVE_PID_IN_UTMP
	ut->ut_pid = li->pid;
# endif

	/* If we're logging out, leave all other fields blank */
	যদি (li->type == LTYPE_LOGOUT)
		প্রত্যাগম;

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
	যদি (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMP
	/* this is just a 128-bit IPv6 address */
	যদি (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((সংরচনা sockaddr_in6 *)&li->hostaddr.sa);
		memcpy(ut->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		যদি (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
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

#যদি defined(USE_UTMPX) || defined (USE_WTMPX)
/* build the utmpx structure */
শূন্য
set_utmpx_time(সংরচনা logininfo *li, সংরচনা utmpx *utx)
{
# যদি defined(HAVE_TV_IN_UTMPX)
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMPX)
	utx->ut_time = li->tv_sec;
# endif
}

শূন্য
construct_utmpx(সংরচনা logininfo *li, সংরচনা utmpx *utx)
{
# ifdef HAVE_ADDR_V6_IN_UTMPX
	সংরচনা sockaddr_in6 *sa6;
#  endif
	memset(utx, '\0', পরিমাণ(*utx));

# ifdef HAVE_ID_IN_UTMPX
	সারি_abbrevname(utx->ut_id, li->সারি, পরিমাণ(utx->ut_id));
# endif

	/* this is done here to keep utmp constants out of loginrec.h */
	বিকল্প (li->type) {
	পক্ষ LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		ভঙ্গ;
	পক্ষ LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		ভঙ্গ;
	}
	সারি_stripname(utx->ut_সারি, li->সারি, পরিমাণ(utx->ut_সারি));
	set_utmpx_time(li, utx);
	utx->ut_pid = li->pid;

	/* strncpy(): Don't necessarily want null termination */
	strncpy(utx->ut_user, li->username,
	    MIN_SIZEOF(utx->ut_user, li->username));

	যদি (li->type == LTYPE_LOGOUT)
		প্রত্যাগম;

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
	যদি (li->hostaddr.sa.sa_family == AF_INET)
		utx->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMPX
	/* this is just a 128-bit IPv6 address */
	যদি (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((সংরচনা sockaddr_in6 *)&li->hostaddr.sa);
		memcpy(utx->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		যদি (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			utx->ut_addr_v6[0] = utx->ut_addr_v6[3];
			utx->ut_addr_v6[1] = 0;
			utx->ut_addr_v6[2] = 0;
			utx->ut_addr_v6[3] = 0;
		}
	}
# endif
# ifdef HAVE_SYSLEN_IN_UTMPX
	/* ut_syslen is the length of the utx_host string */
	utx->ut_syslen = MINIMUM(strlen(li->hostname), পরিমাণ(utx->ut_host));
# endif
}
#endif /* USE_UTMPX || USE_WTMPX */

/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */
#ifdef USE_UTMP

/* if we can, use pututline() etc. */
# যদি !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
	defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
# endif


/* write a utmp entry with the system's help (pututline() and pals) */
# ifdef UTMP_USE_LIBRARY
স্থির পূর্ণাঙ্ক
utmp_write_library(সংরচনা logininfo *li, সংরচনা utmp *ut)
{
	setutent();
	pututline(ut);
#  ifdef HAVE_ENDUTENT
	endutent();
#  endif
	প্রত্যাগম (1);
}
# অন্যথা /* UTMP_USE_LIBRARY */

/*
 * Write a utmp entry direct to the file
 * This is a slightly modification of code in OpenBSD's login.c
 */
স্থির পূর্ণাঙ্ক
utmp_write_direct(সংরচনা logininfo *li, সংরচনা utmp *ut)
{
	সংরচনা utmp old_ut;
	পঞ্জিকা পূর্ণাঙ্ক fd;
	পূর্ণাঙ্ক tty;

	/* FIXME: (ATL) ttyslot() needs local implementation */

#যদি defined(HAVE_GETTTYENT)
	সংরচনা ttyent *ty;

	tty=0;
	setttyent();
	যাবত্ (রিক্ত != (ty = getttyent())) {
		tty++;
		যদি (!strncmp(ty->ty_name, ut->ut_সারি, পরিমাণ(ut->ut_সারি)))
			ভঙ্গ;
	}
	endttyent();

	যদি (রিক্ত == ty) {
		logit_f("tty not found");
		প্রত্যাগম (0);
	}
#অন্যথা /* FIXME */

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

#endif /* HAVE_GETTTYENT */

	যদি (tty > 0 && (fd = open(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		off_t pos, ret;

		pos = (off_t)tty * পরিমাণ(সংরচনা utmp);
		যদি ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			প্রত্যাগম (0);
		}
		যদি (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			প্রত্যাগম (0);
		}
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		যদি (atomicio(পঠ, fd, &old_ut, পরিমাণ(old_ut)) == পরিমাণ(old_ut) &&
		    (ut->ut_host[0] == '\0') && (old_ut.ut_host[0] != '\0') &&
		    (strncmp(old_ut.ut_সারি, ut->ut_সারি, পরিমাণ(ut->ut_সারি)) == 0) &&
		    (strncmp(old_ut.ut_name, ut->ut_name, পরিমাণ(ut->ut_name)) == 0))
			memcpy(ut->ut_host, old_ut.ut_host, পরিমাণ(ut->ut_host));

		যদি ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			প্রত্যাগম (0);
		}
		যদি (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			প্রত্যাগম (0);
		}
		যদি (atomicio(vwrite, fd, ut, পরিমাণ(*ut)) != পরিমাণ(*ut)) {
			logit("%s: error writing %s: %s", __func__,
			    UTMP_FILE, strerror(errno));
			close(fd);
			প্রত্যাগম (0);
		}

		close(fd);
		প্রত্যাগম (1);
	} অন্যথা {
		প্রত্যাগম (0);
	}
}
# endif /* UTMP_USE_LIBRARY */

স্থির পূর্ণাঙ্ক
utmp_perform_login(সংরচনা logininfo *li)
{
	সংরচনা utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	যদি (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		প্রত্যাগম (0);
	}
# অন্যথা
	যদি (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		প্রত্যাগম (0);
	}
# endif
	প্রত্যাগম (1);
}


স্থির পূর্ণাঙ্ক
utmp_perform_logout(সংরচনা logininfo *li)
{
	সংরচনা utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	যদি (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		প্রত্যাগম (0);
	}
# অন্যথা
	যদি (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		প্রত্যাগম (0);
	}
# endif
	প্রত্যাগম (1);
}


পূর্ণাঙ্ক
utmp_write_entry(সংরচনা logininfo *li)
{
	বিকল্প(li->type) {
	পক্ষ LTYPE_LOGIN:
		প্রত্যাগম (utmp_perform_login(li));

	পক্ষ LTYPE_LOGOUT:
		প্রত্যাগম (utmp_perform_logout(li));

	স্বভাব:
		logit_f("invalid type field");
		প্রত্যাগম (0);
	}
}
#endif /* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#ifdef USE_UTMPX

/* if we have the wherewithal, use pututxline etc. */
# যদি !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) && \
	defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
# endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
# ifdef UTMPX_USE_LIBRARY
স্থির পূর্ণাঙ্ক
utmpx_write_library(সংরচনা logininfo *li, সংরচনা utmpx *utx)
{
	setutxent();
	pututxline(utx);

#  ifdef HAVE_ENDUTXENT
	endutxent();
#  endif
	প্রত্যাগম (1);
}

# অন্যথা /* UTMPX_USE_LIBRARY */

/* write a utmp entry direct to the file */
স্থির পূর্ণাঙ্ক
utmpx_write_direct(সংরচনা logininfo *li, সংরচনা utmpx *utx)
{
	logit_f("not implemented!");
	প্রত্যাগম (0);
}
# endif /* UTMPX_USE_LIBRARY */

স্থির পূর্ণাঙ্ক
utmpx_perform_login(সংরচনা logininfo *li)
{
	সংরচনা utmpx utx;

	construct_utmpx(li, &utx);
# ifdef UTMPX_USE_LIBRARY
	যদি (!utmpx_write_library(li, &utx)) {
		logit_f("utmp_write_library() failed");
		প্রত্যাগম (0);
	}
# অন্যথা
	যদি (!utmpx_write_direct(li, &utx)) {
		logit_f("utmp_write_direct() failed");
		প্রত্যাগম (0);
	}
# endif
	প্রত্যাগম (1);
}


স্থির পূর্ণাঙ্ক
utmpx_perform_logout(সংরচনা logininfo *li)
{
	সংরচনা utmpx utx;

	construct_utmpx(li, &utx);
# ifdef HAVE_ID_IN_UTMPX
	সারি_abbrevname(utx.ut_id, li->সারি, পরিমাণ(utx.ut_id));
# endif
# ifdef HAVE_TYPE_IN_UTMPX
	utx.ut_type = DEAD_PROCESS;
# endif

# ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
# অন্যথা
	utmpx_write_direct(li, &utx);
# endif
	প্রত্যাগম (1);
}

পূর্ণাঙ্ক
utmpx_write_entry(সংরচনা logininfo *li)
{
	বিকল্প(li->type) {
	পক্ষ LTYPE_LOGIN:
		প্রত্যাগম (utmpx_perform_login(li));
	পক্ষ LTYPE_LOGOUT:
		প্রত্যাগম (utmpx_perform_logout(li));
	স্বভাব:
		logit_f("invalid type field");
		প্রত্যাগম (0);
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
স্থির পূর্ণাঙ্ক
wtmp_write(সংরচনা logininfo *li, সংরচনা utmp *ut)
{
	সংরচনা stat buf;
	পূর্ণাঙ্ক fd, ret = 1;

	যদি ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem writing %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		প্রত্যাগম (0);
	}
	যদি (fstat(fd, &buf) == 0)
		যদি (atomicio(vwrite, fd, ut, পরিমাণ(*ut)) != পরিমাণ(*ut)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMP_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);
	প্রত্যাগম (ret);
}

স্থির পূর্ণাঙ্ক
wtmp_perform_login(সংরচনা logininfo *li)
{
	সংরচনা utmp ut;

	construct_utmp(li, &ut);
	প্রত্যাগম (wtmp_write(li, &ut));
}


স্থির পূর্ণাঙ্ক
wtmp_perform_logout(সংরচনা logininfo *li)
{
	সংরচনা utmp ut;

	construct_utmp(li, &ut);
	প্রত্যাগম (wtmp_write(li, &ut));
}


পূর্ণাঙ্ক
wtmp_write_entry(সংরচনা logininfo *li)
{
	বিকল্প(li->type) {
	পক্ষ LTYPE_LOGIN:
		প্রত্যাগম (wtmp_perform_login(li));
	পক্ষ LTYPE_LOGOUT:
		প্রত্যাগম (wtmp_perform_logout(li));
	স্বভাব:
		logit_f("invalid type field");
		প্রত্যাগম (0);
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
স্থির পূর্ণাঙ্ক
wtmp_islogin(সংরচনা logininfo *li, সংরচনা utmp *ut)
{
	যদি (strncmp(li->username, ut->ut_name,
	    MIN_SIZEOF(li->username, ut->ut_name)) == 0) {
# ifdef HAVE_TYPE_IN_UTMP
		যদি (ut->ut_type & USER_PROCESS)
			প্রত্যাগম (1);
# অন্যথা
		প্রত্যাগম (1);
# endif
	}
	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
wtmp_get_entry(সংরচনা logininfo *li)
{
	সংরচনা stat st;
	সংরচনা utmp ut;
	পূর্ণাঙ্ক fd, found = 0;

	/* Clear the time entries in our logininfo */
	li->tv_sec = li->tv_usec = 0;

	যদি ((fd = open(WTMP_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		প্রত্যাগম (0);
	}
	যদি (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		close(fd);
		প্রত্যাগম (0);
	}

	/* Seek to the start of the last struct utmp */
	যদি (lseek(fd, -(off_t)পরিমাণ(সংরচনা utmp), SEEK_END) == -1) {
		/* Looks like we've got a fresh wtmp file */
		close(fd);
		প্রত্যাগম (0);
	}

	যাবত্ (!found) {
		যদি (atomicio(পঠ, fd, &ut, পরিমাণ(ut)) != পরিমাণ(ut)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMP_FILE, strerror(errno));
			close (fd);
			প্রত্যাগম (0);
		}
		যদি (wtmp_islogin(li, &ut) ) {
			found = 1;
			/*
			 * We've already checked for a time in struct
			 * utmp, in login_getlast()
			 */
# ifdef HAVE_TIME_IN_UTMP
			li->tv_sec = ut.ut_time;
# অন্যথা
#  যদি HAVE_TV_IN_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
# endif
			সারি_fullname(li->সারি, ut.ut_সারি,
			    MIN_SIZEOF(li->সারি, ut.ut_সারি));
# ifdef HAVE_HOST_IN_UTMP
			strlcpy(li->hostname, ut.ut_host,
			    MIN_SIZEOF(li->hostname, ut.ut_host));
# endif
			অনুবর্ত;
		}
		/* Seek back 2 x struct utmp */
		যদি (lseek(fd, -(off_t)(2 * পরিমাণ(সংরচনা utmp)), SEEK_CUR) == -1) {
			/* We've found the start of the file, so quit */
			close(fd);
			প্রত্যাগম (0);
		}
	}

	/* We found an entry. Tidy up and return */
	close(fd);
	প্রত্যাগম (1);
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
স্থির পূর্ণাঙ্ক
wtmpx_write(সংরচনা logininfo *li, সংরচনা utmpx *utx)
{
#ifndef HAVE_UPDWTMPX
	সংরচনা stat buf;
	পূর্ণাঙ্ক fd, ret = 1;

	যদি ((fd = open(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		প্রত্যাগম (0);
	}

	যদি (fstat(fd, &buf) == 0)
		যদি (atomicio(vwrite, fd, utx, পরিমাণ(*utx)) != পরিমাণ(*utx)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);

	প্রত্যাগম (ret);
#অন্যথা
	updwtmpx(WTMPX_FILE, utx);
	প্রত্যাগম (1);
#endif
}


স্থির পূর্ণাঙ্ক
wtmpx_perform_login(সংরচনা logininfo *li)
{
	সংরচনা utmpx utx;

	construct_utmpx(li, &utx);
	প্রত্যাগম (wtmpx_write(li, &utx));
}


স্থির পূর্ণাঙ্ক
wtmpx_perform_logout(সংরচনা logininfo *li)
{
	সংরচনা utmpx utx;

	construct_utmpx(li, &utx);
	প্রত্যাগম (wtmpx_write(li, &utx));
}


পূর্ণাঙ্ক
wtmpx_write_entry(সংরচনা logininfo *li)
{
	বিকল্প(li->type) {
	পক্ষ LTYPE_LOGIN:
		প্রত্যাগম (wtmpx_perform_login(li));
	পক্ষ LTYPE_LOGOUT:
		প্রত্যাগম (wtmpx_perform_logout(li));
	স্বভাব:
		logit_f("invalid type field");
		প্রত্যাগম (0);
	}
}

/* Please see the notes above wtmp_islogin() for information about the
   next two functions */

/* Return true if this wtmpx entry indicates a login */
স্থির পূর্ণাঙ্ক
wtmpx_islogin(সংরচনা logininfo *li, সংরচনা utmpx *utx)
{
	যদি (strncmp(li->username, utx->ut_user,
	    MIN_SIZEOF(li->username, utx->ut_user)) == 0 ) {
# ifdef HAVE_TYPE_IN_UTMPX
		যদি (utx->ut_type == USER_PROCESS)
			প্রত্যাগম (1);
# অন্যথা
		প্রত্যাগম (1);
# endif
	}
	প্রত্যাগম (0);
}


পূর্ণাঙ্ক
wtmpx_get_entry(সংরচনা logininfo *li)
{
	সংরচনা stat st;
	সংরচনা utmpx utx;
	পূর্ণাঙ্ক fd, found=0;

	/* Clear the time entries */
	li->tv_sec = li->tv_usec = 0;

	যদি ((fd = open(WTMPX_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		প্রত্যাগম (0);
	}
	যদি (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		close(fd);
		প্রত্যাগম (0);
	}

	/* Seek to the start of the last struct utmpx */
	যদি (lseek(fd, -(off_t)পরিমাণ(সংরচনা utmpx), SEEK_END) == -1 ) {
		/* probably a newly rotated wtmpx file */
		close(fd);
		প্রত্যাগম (0);
	}

	যাবত্ (!found) {
		যদি (atomicio(পঠ, fd, &utx, পরিমাণ(utx)) != পরিমাণ(utx)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			close (fd);
			প্রত্যাগম (0);
		}
		/*
		 * Logouts are recorded as a blank username on a particular
		 * line. So, we just need to find the username in struct utmpx
		 */
		যদি (wtmpx_islogin(li, &utx)) {
			found = 1;
# যদি defined(HAVE_TV_IN_UTMPX)
			li->tv_sec = utx.ut_tv.tv_sec;
# elif defined(HAVE_TIME_IN_UTMPX)
			li->tv_sec = utx.ut_time;
# endif
			সারি_fullname(li->সারি, utx.ut_সারি, পরিমাণ(li->সারি));
# যদি defined(HAVE_HOST_IN_UTMPX)
			strlcpy(li->hostname, utx.ut_host,
			    MIN_SIZEOF(li->hostname, utx.ut_host));
# endif
			অনুবর্ত;
		}
		যদি (lseek(fd, -(off_t)(2 * পরিমাণ(সংরচনা utmpx)), SEEK_CUR) == -1) {
			close(fd);
			প্রত্যাগম (0);
		}
	}

	close(fd);
	প্রত্যাগম (1);
}
#endif /* USE_WTMPX */

#ifdef USE_WTMPDB
স্থির পূর্ণাঙ্ক
wtmpdb_perform_login(সংরচনা logininfo *li)
{
	uint64_t login_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	    li->tv_usec;
	ধ্রুব বর্ণ *tty;

	যদি (strncmp(li->সারি, "/dev/", 5) == 0)
		tty = &(li->সারি[5]);
	অন্যথা
		tty = li->সারি;

	li->wtmpdb_id = wtmpdb_login(রিক্ত, USER_PROCESS, li->username,
	    login_time, tty, li->hostname, 0, 0);

	যদি (li->wtmpdb_id < 0)
		প্রত্যাগম (0);

	প্রত্যাগম (1);
}

স্থির পূর্ণাঙ্ক
wtmpdb_perform_logout(সংরচনা logininfo *li)
{
	uint64_t logout_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	   li->tv_usec;

	যদি (li->wtmpdb_id == 0) {
		ধ্রুব বর্ণ *tty;

		যদি (strncmp(li->সারি, "/dev/", 5) == 0)
			tty = &(li->সারি[5]);
		অন্যথা
			tty = li->সারি;

		li->wtmpdb_id = wtmpdb_get_id(রিক্ত, tty, রিক্ত);
	}
	wtmpdb_logout(রিক্ত, li->wtmpdb_id, logout_time, রিক্ত);

	প্রত্যাগম (1);
}

পূর্ণাঙ্ক
wtmpdb_write_entry(সংরচনা logininfo *li)
{
	বিকল্প(li->type) {
	পক্ষ LTYPE_LOGIN:
		প্রত্যাগম (wtmpdb_perform_login(li));
	পক্ষ LTYPE_LOGOUT:
		প্রত্যাগম (wtmpdb_perform_logout(li));
	স্বভাব:
		logit_f("invalid type field");
		প্রত্যাগম (0);
	}
}
#endif

/**
 ** Low-level libutil login() functions
 **/

#ifdef USE_LOGIN
স্থির পূর্ণাঙ্ক
syslogin_perform_login(সংরচনা logininfo *li)
{
	সংরচনা utmp *ut;

	ut = xmalloc(পরিমাণ(*ut));
	construct_utmp(li, ut);
	login(ut);
	মুক্ত(ut);

	প্রত্যাগম (1);
}

স্থির পূর্ণাঙ্ক
syslogin_perform_logout(সংরচনা logininfo *li)
{
# ifdef HAVE_LOGOUT
	বর্ণ সারি[UT_LINESIZE];

	(শূন্য)সারি_stripname(সারি, li->সারি, পরিমাণ(সারি));

	যদি (!logout(সারি))
		logit_f("logout() returned an error");
#  ifdef HAVE_LOGWTMP
	অন্যথা
		logwtmp(সারি, "", "");
#  endif
	/* FIXME: (ATL - if the need arises) What to do if we have
	 * login, but no logout?  what if logout but no logwtmp? All
	 * routines are in libutil so they should all be there,
	 * but... */
# endif
	প্রত্যাগম (1);
}

পূর্ণাঙ্ক
syslogin_write_entry(সংরচনা logininfo *li)
{
	বিকল্প (li->type) {
	পক্ষ LTYPE_LOGIN:
		প্রত্যাগম (syslogin_perform_login(li));
	পক্ষ LTYPE_LOGOUT:
		প্রত্যাগম (syslogin_perform_logout(li));
	স্বভাব:
		logit_f("Invalid type field");
		প্রত্যাগম (0);
	}
}
#endif /* USE_LOGIN */

/* end of file log-syslogin.c */

/**
 ** Low-level lastlog functions
 **/

#ifdef USE_LASTLOG

#যদি !defined(LASTLOG_WRITE_PUTUTXLINE) || !defined(HAVE_GETLASTLOGXBYNAME)
/* open the file (using filemode) and seek to the login entry */
স্থির পূর্ণাঙ্ক
lastlog_openseek(সংরচনা logininfo *li, পূর্ণাঙ্ক *fd, পূর্ণাঙ্ক filemode)
{
	off_t offset;
	বর্ণ lastlog_file[1024];
	সংরচনা stat st;

	যদি (stat(LASTLOG_FILE, &st) != 0) {
		logit("%s: Couldn't stat %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		প্রত্যাগম (0);
	}
	যদি (S_ISDIR(st.st_mode)) {
		snprintf(lastlog_file, পরিমাণ(lastlog_file), "%s/%s",
		    LASTLOG_FILE, li->username);
	} অন্যথা যদি (S_ISREG(st.st_mode)) {
		strlcpy(lastlog_file, LASTLOG_FILE, পরিমাণ(lastlog_file));
	} অন্যথা {
		logit("%s: %.100s is not a file or directory!", __func__,
		    LASTLOG_FILE);
		প্রত্যাগম (0);
	}

	*fd = open(lastlog_file, filemode, 0600);
	যদি (*fd < 0) {
		debug("%s: Couldn't open %s: %s", __func__,
		    lastlog_file, strerror(errno));
		প্রত্যাগম (0);
	}

	যদি (S_ISREG(st.st_mode)) {
		/* find this uid's offset in the lastlog file */
		offset = (off_t) ((u_long)li->uid * পরিমাণ(সংরচনা lastlog));

		যদি (lseek(*fd, offset, SEEK_SET) != offset) {
			logit("%s: %s->lseek(): %s", __func__,
			    lastlog_file, strerror(errno));
			close(*fd);
			প্রত্যাগম (0);
		}
	}

	প্রত্যাগম (1);
}
#endif /* !LASTLOG_WRITE_PUTUTXLINE || !HAVE_GETLASTLOGXBYNAME */

#ifdef LASTLOG_WRITE_PUTUTXLINE
পূর্ণাঙ্ক
lastlog_write_entry(সংরচনা logininfo *li)
{
	বিকল্প(li->type) {
	পক্ষ LTYPE_LOGIN:
		প্রত্যাগম 1; /* lastlog written by pututxline */
	স্বভাব:
		logit("lastlog_write_entry: Invalid type field");
		প্রত্যাগম 0;
	}
}
#অন্যথা /* LASTLOG_WRITE_PUTUTXLINE */
পূর্ণাঙ্ক
lastlog_write_entry(সংরচনা logininfo *li)
{
	সংরচনা lastlog last;
	পূর্ণাঙ্ক fd;

	বিকল্প(li->type) {
	পক্ষ LTYPE_LOGIN:
		/* create our struct lastlog */
		memset(&last, '\0', পরিমাণ(last));
		সারি_stripname(last.ll_সারি, li->সারি, পরিমাণ(last.ll_সারি));
		strlcpy(last.ll_host, li->hostname,
		    MIN_SIZEOF(last.ll_host, li->hostname));
		last.ll_time = li->tv_sec;

		যদি (!lastlog_openseek(li, &fd, O_RDWR|O_CREAT))
			প্রত্যাগম (0);

		/* write the entry */
		যদি (atomicio(vwrite, fd, &last, পরিমাণ(last)) != পরিমাণ(last)) {
			close(fd);
			logit("%s: Error writing to %s: %s", __func__,
			    LASTLOG_FILE, strerror(errno));
			প্রত্যাগম (0);
		}

		close(fd);
		প্রত্যাগম (1);
	স্বভাব:
		logit_f("Invalid type field");
		প্রত্যাগম (0);
	}
}
#endif /* LASTLOG_WRITE_PUTUTXLINE */

#ifdef HAVE_GETLASTLOGXBYNAME
পূর্ণাঙ্ক
lastlog_get_entry(সংরচনা logininfo *li)
{
	সংরচনা lastlogx l, *ll;

	যদি ((ll = getlastlogxbyname(li->username, &l)) == রিক্ত) {
		memset(&l, '\0', পরিমাণ(l));
		ll = &l;
	}
	সারি_fullname(li->সারি, ll->ll_সারি, পরিমাণ(li->সারি));
	strlcpy(li->hostname, ll->ll_host,
		MIN_SIZEOF(li->hostname, ll->ll_host));
	li->tv_sec = ll->ll_tv.tv_sec;
	li->tv_usec = ll->ll_tv.tv_usec;
	প্রত্যাগম (1);
}
#অন্যথা /* HAVE_GETLASTLOGXBYNAME */
পূর্ণাঙ্ক
lastlog_get_entry(সংরচনা logininfo *li)
{
	সংরচনা lastlog last;
	পূর্ণাঙ্ক fd, ret;

	যদি (!lastlog_openseek(li, &fd, O_RDONLY))
		প্রত্যাগম (0);

	ret = atomicio(পঠ, fd, &last, পরিমাণ(last));
	close(fd);

	বিকল্প (ret) {
	পক্ষ 0:
		memset(&last, '\0', পরিমাণ(last));
		/* FALLTHRU */
	পক্ষ পরিমাণ(last):
		সারি_fullname(li->সারি, last.ll_সারি, পরিমাণ(li->সারি));
		strlcpy(li->hostname, last.ll_host,
		    MIN_SIZEOF(li->hostname, last.ll_host));
		li->tv_sec = last.ll_time;
		প্রত্যাগম (1);
	পক্ষ -1:
		error("%s: Error reading from %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		প্রত্যাগম (0);
	স্বভাব:
		error("%s: Error reading from %s: Expecting %d, got %d",
		    __func__, LASTLOG_FILE, (পূর্ণাঙ্ক)পরিমাণ(last), ret);
		প্রত্যাগম (0);
	}

	/* NOTREACHED */
	প্রত্যাগম (0);
}
#endif /* HAVE_GETLASTLOGXBYNAME */
#endif /* USE_LASTLOG */

#যদি defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
পূর্ণাঙ্ক
utmpx_get_entry(সংরচনা logininfo *li)
{
	সংরচনা utmpx *utx;

	যদি (setutxdb(UTXDB_LASTLOGIN, রিক্ত) != 0)
		প্রত্যাগম (0);
	utx = getutxuser(li->username);
	যদি (utx == রিক্ত) {
		endutxent();
		প্রত্যাগম (0);
	}

	সারি_fullname(li->সারি, utx->ut_সারি,
	    MIN_SIZEOF(li->সারি, utx->ut_সারি));
	strlcpy(li->hostname, utx->ut_host,
	    MIN_SIZEOF(li->hostname, utx->ut_host));
	li->tv_sec = utx->ut_tv.tv_sec;
	li->tv_usec = utx->ut_tv.tv_usec;
	endutxent();
	প্রত্যাগম (1);
}
#endif /* USE_UTMPX && HAVE_SETUTXDB && UTXDB_LASTLOGIN && HAVE_GETUTXUSER */

#ifdef USE_BTMP
/*
 * Logs failed login attempts in _PATH_BTMP if that exists.
 * The most common login failure is to give password instead of username.
 * So the _PATH_BTMP file is checked for the correct permission, so that only
 * root can read it.
 */
শূন্য
record_failed_login(সংরচনা ssh *ssh, ধ্রুব বর্ণ *username, ধ্রুব বর্ণ *hostname,
    ধ্রুব বর্ণ *ttyn)
{
	পূর্ণাঙ্ক fd;
	সংরচনা utmp ut;
	সংরচনা logininfo li;
	socklen_t fromlen = পরিমাণ(li.hostaddr);
	time_t t;
	সংরচনা stat fst;

	যদি (geteuid() != 0)
		প্রত্যাগম;
	যদি ((fd = open(_PATH_BTMP, O_WRONLY | O_APPEND)) < 0) {
		debug("Unable to open the btmp file %s: %s", _PATH_BTMP,
		    strerror(errno));
		প্রত্যাগম;
	}
	যদি (fstat(fd, &fst) < 0) {
		logit("%s: fstat of %s failed: %s", __func__, _PATH_BTMP,
		    strerror(errno));
		গচ্ছ out;
	}
	যদি ((fst.st_mode & (S_IXGRP | S_IRWXO)) || fst.st_uid != 0) {
		logit("Excess permission or bad ownership on file %s",
		    _PATH_BTMP);
		গচ্ছ out;
	}

	/* Construct a logininfo and turn it into a utmp */
	memset(&li, 0, পরিমাণ(li));
	li.type = LTYPE_FAILED;
	li.pid = getpid();
	strlcpy(li.সারি, "ssh:notty", পরিমাণ(li.সারি));
	strlcpy(li.username, username, পরিমাণ(li.username));
	strlcpy(li.hostname, hostname, পরিমাণ(li.hostname));
	time(&t);
	li.tv_sec = t > 0 ? (unsigned long)t : 0;
	যদি (ssh_packet_connection_is_on_socket(ssh)) {
		(শূন্য)getpeername(ssh_packet_get_connection_in(ssh),
		    &li.hostaddr.sa, &fromlen);
	}
	construct_utmp(&li, &ut);

	যদি (atomicio(vwrite, fd, &ut, পরিমাণ(ut)) != পরিমাণ(ut)) {
		error("Failed to write to %s: %s", _PATH_BTMP,
		    strerror(errno));
	}
out:
	close(fd);
}
#endif	/* USE_BTMP */
