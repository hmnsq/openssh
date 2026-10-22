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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <sys/socket.h>
#شامل <sys/time.h>

#شامل <netinet/in.h>

#شامل <stdlib.h>
#شامل <errno.h>
#شامل <fcntl.h>
#شامل <paths.h>
#شامل <pwd.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <time.h>
#شامل <unistd.h>

#شامل "xmalloc.h"
#شامل "sshkey.h"
#شامل "hostfile.h"
#شامل "ssh.h"
#شامل "loginrec.h"
#شامل "log.h"
#شامل "atomicio.h"
#شامل "packet.h"
#شامل "canohost.h"
#شامل "auth.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "misc.h"

# include <util.h>

#ifdef USE_WTMPDB
# include <wtmpdb.h>
#endif

/**
 ** prototypes for helper functions in this file
 **/

#اگر HAVE_UTMP_H
تهی set_utmp_time(ساختار logininfo *li, ساختار utmp *ut);
تهی construct_utmp(ساختار logininfo *li, ساختار utmp *ut);
#endif

#ifdef HAVE_UTMPX_H
تهی set_utmpx_time(ساختار logininfo *li, ساختار utmpx *ut);
تهی construct_utmpx(ساختار logininfo *li, ساختار utmpx *ut);
#endif

صحیح utmp_write_entry(ساختار logininfo *li);
صحیح utmpx_write_entry(ساختار logininfo *li);
صحیح wtmp_write_entry(ساختار logininfo *li);
صحیح wtmpx_write_entry(ساختار logininfo *li);
صحیح lastlog_write_entry(ساختار logininfo *li);
صحیح syslogin_write_entry(ساختار logininfo *li);
#ifdef USE_WTMPDB
صحیح wtmpdb_write_entry(ساختار logininfo *li);
#endif

صحیح getlast_entry(ساختار logininfo *li);
صحیح lastlog_get_entry(ساختار logininfo *li);
صحیح utmpx_get_entry(ساختار logininfo *li);
صحیح wtmp_get_entry(ساختار logininfo *li);
صحیح wtmpx_get_entry(ساختار logininfo *li);

بیرونی ساختار sshbuf *loginmsg;

/* pick the shortest string */
#define MIN_SIZEOF(s1,s2) (اندازه(s1) < اندازه(s2) ? اندازه(s1) : اندازه(s2))

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
صحیح
login_login(ساختار logininfo *li)
{
	li->type = LTYPE_LOGIN;
	بازگشت (login_write(li));
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
صحیح
login_logout(ساختار logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	بازگشت (login_write(li));
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
unsigned صحیح
login_get_lastlog_time(ثابت uid_t uid)
{
	ساختار logininfo li;

	اگر (login_get_lastlog(&li, uid))
		بازگشت (li.tv_sec);
	وگرنه
		بازگشت (0);
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
ساختار logininfo *
login_get_lastlog(ساختار logininfo *li, ثابت uid_t uid)
{
	ساختار passwd *pw;

	memset(li, '\0', اندازه(*li));
	li->uid = uid;

	/*
	 * If we don't have a 'real' lastlog, we need the username to
	 * reliably search wtmp(x) for the last login (see
	 * wtmp_get_entry().)
	 */
	pw = getpwuid(uid);
	اگر (pw == پوچ)
		fatal("%s: Cannot find account for uid %ld", __func__,
		    (long)uid);

	اگر (strlcpy(li->username, pw->pw_name, اندازه(li->username)) >=
	    اندازه(li->username)) {
		error("%s: username too long (%lu > max %lu)", __func__,
		    (unsigned long)strlen(pw->pw_name),
		    (unsigned long)اندازه(li->username) - 1);
		بازگشت پوچ;
	}

	اگر (getlast_entry(li))
		بازگشت (li);
	وگرنه
		بازگشت (پوچ);
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
ساختار
logininfo *login_alloc_entry(pid_t pid, ثابت نویسه *username,
    ثابت نویسه *hostname, ثابت نویسه *سطر)
{
	ساختار logininfo *newli;

	newli = xmalloc(اندازه(*newli));
	login_init_entry(newli, pid, username, hostname, سطر);
	بازگشت (newli);
}


/* login_free_entry(struct logininfo *)    - free struct memory */
تهی
login_free_entry(ساختار logininfo *li)
{
	آزاد(li);
}


/* login_init_entry(struct logininfo *, int, char*, char*, char*)
 *                                        - initialise a struct logininfo
 *
 * Populates a new struct logininfo, a data structure meant to carry
 * the information required to portably record login info.
 *
 * Returns: 1
 */
صحیح
login_init_entry(ساختار logininfo *li, pid_t pid, ثابت نویسه *username,
    ثابت نویسه *hostname, ثابت نویسه *سطر)
{
	ساختار passwd *pw;

	memset(li, 0, اندازه(*li));

	li->pid = pid;

	/* set the line information */
	اگر (سطر)
		سطر_fullname(li->سطر, سطر, اندازه(li->سطر));

	اگر (username) {
		strlcpy(li->username, username, اندازه(li->username));
		pw = getpwnam(li->username);
		اگر (pw == پوچ) {
			fatal("%s: Cannot find user \"%s\"", __func__,
			    li->username);
		}
		li->uid = pw->pw_uid;
	}

	اگر (hostname)
		strlcpy(li->hostname, hostname, اندازه(li->hostname));

	بازگشت (1);
}

/*
 * login_set_current_time(struct logininfo *)    - set the current time
 *
 * Set the current time in a logininfo structure. This function is
 * meant to eliminate the need to deal with system dependencies for
 * time handling.
 */
تهی
login_set_current_time(ساختار logininfo *li)
{
	ساختار timeval tv;

	gettimeofday(&tv, پوچ);

	li->tv_sec = tv.tv_sec;
	li->tv_usec = tv.tv_usec;
}

/* copy a sockaddr_* into our logininfo */
تهی
login_set_addr(ساختار logininfo *li, ثابت ساختار sockaddr *sa,
    ثابت unsigned صحیح sa_size)
{
	unsigned صحیح bufsize = sa_size;

	/* make sure we don't overrun our union */
	اگر (اندازه(li->hostaddr) < sa_size)
		bufsize = اندازه(li->hostaddr);

	memcpy(&li->hostaddr.sa, sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/
صحیح
login_write(ساختار logininfo *li)
{
#ifndef HAVE_CYGWIN
	اگر (geteuid() != 0) {
		logit("Attempt to write login records by non-root user (aborting)");
		بازگشت (1);
	}
#endif

	/* set the timestamp */
	login_set_current_time(li);
#ifdef USE_LOGIN
	syslogin_write_entry(li);
#endif
#ifdef USE_LASTLOG
	اگر (li->type == LTYPE_LOGIN)
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
	اگر (li->type == LTYPE_LOGIN &&
	    !sys_auth_record_login(li->username,li->hostname,li->سطر,
	    loginmsg))
		logit("Writing login record failed for %s", li->username);
#endif
#ifdef SSH_AUDIT_EVENTS
	اگر (li->type == LTYPE_LOGIN)
		audit_session_open(li);
	وگرنه اگر (li->type == LTYPE_LOGOUT)
		audit_session_close(li);
#endif
	بازگشت (0);
}

#ifdef LOGIN_NEEDS_UTMPX
صحیح
login_utmp_only(ساختار logininfo *li)
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
	بازگشت (0);
}
#endif

/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
صحیح
getlast_entry(ساختار logininfo *li)
{
#ifdef USE_LASTLOG
	بازگشت(lastlog_get_entry(li));
#وگرنه /* !USE_LASTLOG */
#اگر defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
	بازگشت (utmpx_get_entry(li));
#endif

#اگر defined(DISABLE_LASTLOG)
	/* On some systems we shouldn't even try to obtain last login
	 * time, e.g. AIX */
	بازگشت (0);
# elif defined(USE_WTMP) && \
    (defined(HAVE_TIME_IN_UTMP) || defined(HAVE_TV_IN_UTMP))
	/* retrieve last login time from utmp */
	بازگشت (wtmp_get_entry(li));
# elif defined(USE_WTMPX) && \
    (defined(HAVE_TIME_IN_UTMPX) || defined(HAVE_TV_IN_UTMPX))
	/* If wtmp isn't available, try wtmpx */
	بازگشت (wtmpx_get_entry(li));
# وگرنه
	/* Give up: No means of retrieving last login time */
	بازگشت (0);
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
نویسه *
سطر_fullname(نویسه *dst, ثابت نویسه *src, u_int dstsize)
{
	memset(dst, '\0', dstsize);
	اگر ((strncmp(src, "/dev/", 5) == 0) || (dstsize < (strlen(src) + 5)))
		strlcpy(dst, src, dstsize);
	وگرنه {
		strlcpy(dst, "/dev/", dstsize);
		strlcat(dst, src, dstsize);
	}
	بازگشت (dst);
}

/* line_stripname(): strip the leading '/dev' if it exists, return dst */
نویسه *
سطر_stripname(نویسه *dst, ثابت نویسه *src, صحیح dstsize)
{
	memset(dst, '\0', dstsize);
	اگر (strncmp(src, "/dev/", 5) == 0)
		strlcpy(dst, src + 5, dstsize);
	وگرنه
		strlcpy(dst, src, dstsize);
	بازگشت (dst);
}

/*
 * line_abbrevname(): Return the abbreviated (usually four-character)
 * form of the line (Just use the last <dstsize> characters of the
 * full name.)
 *
 * NOTE: use strncpy because we do NOT necessarily want zero
 * termination
 */
نویسه *
سطر_abbrevname(نویسه *dst, ثابت نویسه *src, صحیح dstsize)
{
	size_t len;

	memset(dst, '\0', dstsize);

	اگر (strcmp(src, "ssh:notty") == 0)
		بازگشت dst;

	/* Always skip prefix if present */
	اگر (strncmp(src, "/dev/", 5) == 0)
		src += 5;

#ifdef WITH_ABBREV_NO_TTY
	اگر (strncmp(src, "tty", 3) == 0)
		src += 3;
#endif

	len = strlen(src);

	اگر (len > 0) {
		اگر (((صحیح)len - dstsize) > 0)
			src +=  ((صحیح)len - dstsize);

		/* note: _don't_ change this to strlcpy */
		strncpy(dst, src, (size_t)dstsize);
	}

	بازگشت (dst);
}

/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#اگر defined(USE_BTMP) || defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
تهی
set_utmp_time(ساختار logininfo *li, ساختار utmp *ut)
{
# اگر defined(HAVE_TV_IN_UTMP)
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMP)
	ut->ut_time = li->tv_sec;
# endif
}

تهی
construct_utmp(ساختار logininfo *li,
		    ساختار utmp *ut)
{
# ifdef HAVE_ADDR_V6_IN_UTMP
	ساختار sockaddr_in6 *sa6;
# endif

	memset(ut, '\0', اندازه(*ut));

	/* First fill out fields used for both logins and logouts */

# ifdef HAVE_ID_IN_UTMP
	سطر_abbrevname(ut->ut_id, li->سطر, اندازه(ut->ut_id));
# endif

# ifdef HAVE_TYPE_IN_UTMP
	/* This is done here to keep utmp constants out of struct logininfo */
	انتخاب (li->type) {
	حالت LTYPE_FAILED:
		ut->ut_type = LOGIN_PROCESS;
		بشکن;
	حالت LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		بشکن;
	حالت LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		بشکن;
	}
# endif
	set_utmp_time(li, ut);

	سطر_stripname(ut->ut_سطر, li->سطر, اندازه(ut->ut_سطر));

# ifdef HAVE_PID_IN_UTMP
	ut->ut_pid = li->pid;
# endif

	/* If we're logging out, leave all other fields blank */
	اگر (li->type == LTYPE_LOGOUT)
		بازگشت;

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
	اگر (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMP
	/* this is just a 128-bit IPv6 address */
	اگر (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((ساختار sockaddr_in6 *)&li->hostaddr.sa);
		memcpy(ut->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		اگر (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
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

#اگر defined(USE_UTMPX) || defined (USE_WTMPX)
/* build the utmpx structure */
تهی
set_utmpx_time(ساختار logininfo *li, ساختار utmpx *utx)
{
# اگر defined(HAVE_TV_IN_UTMPX)
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMPX)
	utx->ut_time = li->tv_sec;
# endif
}

تهی
construct_utmpx(ساختار logininfo *li, ساختار utmpx *utx)
{
# ifdef HAVE_ADDR_V6_IN_UTMPX
	ساختار sockaddr_in6 *sa6;
#  endif
	memset(utx, '\0', اندازه(*utx));

# ifdef HAVE_ID_IN_UTMPX
	سطر_abbrevname(utx->ut_id, li->سطر, اندازه(utx->ut_id));
# endif

	/* this is done here to keep utmp constants out of loginrec.h */
	انتخاب (li->type) {
	حالت LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		بشکن;
	حالت LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		بشکن;
	}
	سطر_stripname(utx->ut_سطر, li->سطر, اندازه(utx->ut_سطر));
	set_utmpx_time(li, utx);
	utx->ut_pid = li->pid;

	/* strncpy(): Don't necessarily want null termination */
	strncpy(utx->ut_user, li->username,
	    MIN_SIZEOF(utx->ut_user, li->username));

	اگر (li->type == LTYPE_LOGOUT)
		بازگشت;

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
	اگر (li->hostaddr.sa.sa_family == AF_INET)
		utx->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMPX
	/* this is just a 128-bit IPv6 address */
	اگر (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((ساختار sockaddr_in6 *)&li->hostaddr.sa);
		memcpy(utx->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		اگر (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			utx->ut_addr_v6[0] = utx->ut_addr_v6[3];
			utx->ut_addr_v6[1] = 0;
			utx->ut_addr_v6[2] = 0;
			utx->ut_addr_v6[3] = 0;
		}
	}
# endif
# ifdef HAVE_SYSLEN_IN_UTMPX
	/* ut_syslen is the length of the utx_host string */
	utx->ut_syslen = MINIMUM(strlen(li->hostname), اندازه(utx->ut_host));
# endif
}
#endif /* USE_UTMPX || USE_WTMPX */

/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */
#ifdef USE_UTMP

/* if we can, use pututline() etc. */
# اگر !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
	defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
# endif


/* write a utmp entry with the system's help (pututline() and pals) */
# ifdef UTMP_USE_LIBRARY
ایستا صحیح
utmp_write_library(ساختار logininfo *li, ساختار utmp *ut)
{
	setutent();
	pututline(ut);
#  ifdef HAVE_ENDUTENT
	endutent();
#  endif
	بازگشت (1);
}
# وگرنه /* UTMP_USE_LIBRARY */

/*
 * Write a utmp entry direct to the file
 * This is a slightly modification of code in OpenBSD's login.c
 */
ایستا صحیح
utmp_write_direct(ساختار logininfo *li, ساختار utmp *ut)
{
	ساختار utmp old_ut;
	ثبات صحیح fd;
	صحیح tty;

	/* FIXME: (ATL) ttyslot() needs local implementation */

#اگر defined(HAVE_GETTTYENT)
	ساختار ttyent *ty;

	tty=0;
	setttyent();
	وقتی (پوچ != (ty = getttyent())) {
		tty++;
		اگر (!strncmp(ty->ty_name, ut->ut_سطر, اندازه(ut->ut_سطر)))
			بشکن;
	}
	endttyent();

	اگر (پوچ == ty) {
		logit_f("tty not found");
		بازگشت (0);
	}
#وگرنه /* FIXME */

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

#endif /* HAVE_GETTTYENT */

	اگر (tty > 0 && (fd = open(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		off_t pos, ret;

		pos = (off_t)tty * اندازه(ساختار utmp);
		اگر ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			بازگشت (0);
		}
		اگر (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			بازگشت (0);
		}
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		اگر (atomicio(اقرأ, fd, &old_ut, اندازه(old_ut)) == اندازه(old_ut) &&
		    (ut->ut_host[0] == '\0') && (old_ut.ut_host[0] != '\0') &&
		    (strncmp(old_ut.ut_سطر, ut->ut_سطر, اندازه(ut->ut_سطر)) == 0) &&
		    (strncmp(old_ut.ut_name, ut->ut_name, اندازه(ut->ut_name)) == 0))
			memcpy(ut->ut_host, old_ut.ut_host, اندازه(ut->ut_host));

		اگر ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			بازگشت (0);
		}
		اگر (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			بازگشت (0);
		}
		اگر (atomicio(vwrite, fd, ut, اندازه(*ut)) != اندازه(*ut)) {
			logit("%s: error writing %s: %s", __func__,
			    UTMP_FILE, strerror(errno));
			close(fd);
			بازگشت (0);
		}

		close(fd);
		بازگشت (1);
	} وگرنه {
		بازگشت (0);
	}
}
# endif /* UTMP_USE_LIBRARY */

ایستا صحیح
utmp_perform_login(ساختار logininfo *li)
{
	ساختار utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	اگر (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		بازگشت (0);
	}
# وگرنه
	اگر (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		بازگشت (0);
	}
# endif
	بازگشت (1);
}


ایستا صحیح
utmp_perform_logout(ساختار logininfo *li)
{
	ساختار utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	اگر (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		بازگشت (0);
	}
# وگرنه
	اگر (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		بازگشت (0);
	}
# endif
	بازگشت (1);
}


صحیح
utmp_write_entry(ساختار logininfo *li)
{
	انتخاب(li->type) {
	حالت LTYPE_LOGIN:
		بازگشت (utmp_perform_login(li));

	حالت LTYPE_LOGOUT:
		بازگشت (utmp_perform_logout(li));

	پیشفرض:
		logit_f("invalid type field");
		بازگشت (0);
	}
}
#endif /* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#ifdef USE_UTMPX

/* if we have the wherewithal, use pututxline etc. */
# اگر !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) && \
	defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
# endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
# ifdef UTMPX_USE_LIBRARY
ایستا صحیح
utmpx_write_library(ساختار logininfo *li, ساختار utmpx *utx)
{
	setutxent();
	pututxline(utx);

#  ifdef HAVE_ENDUTXENT
	endutxent();
#  endif
	بازگشت (1);
}

# وگرنه /* UTMPX_USE_LIBRARY */

/* write a utmp entry direct to the file */
ایستا صحیح
utmpx_write_direct(ساختار logininfo *li, ساختار utmpx *utx)
{
	logit_f("not implemented!");
	بازگشت (0);
}
# endif /* UTMPX_USE_LIBRARY */

ایستا صحیح
utmpx_perform_login(ساختار logininfo *li)
{
	ساختار utmpx utx;

	construct_utmpx(li, &utx);
# ifdef UTMPX_USE_LIBRARY
	اگر (!utmpx_write_library(li, &utx)) {
		logit_f("utmp_write_library() failed");
		بازگشت (0);
	}
# وگرنه
	اگر (!utmpx_write_direct(li, &utx)) {
		logit_f("utmp_write_direct() failed");
		بازگشت (0);
	}
# endif
	بازگشت (1);
}


ایستا صحیح
utmpx_perform_logout(ساختار logininfo *li)
{
	ساختار utmpx utx;

	construct_utmpx(li, &utx);
# ifdef HAVE_ID_IN_UTMPX
	سطر_abbrevname(utx.ut_id, li->سطر, اندازه(utx.ut_id));
# endif
# ifdef HAVE_TYPE_IN_UTMPX
	utx.ut_type = DEAD_PROCESS;
# endif

# ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
# وگرنه
	utmpx_write_direct(li, &utx);
# endif
	بازگشت (1);
}

صحیح
utmpx_write_entry(ساختار logininfo *li)
{
	انتخاب(li->type) {
	حالت LTYPE_LOGIN:
		بازگشت (utmpx_perform_login(li));
	حالت LTYPE_LOGOUT:
		بازگشت (utmpx_perform_logout(li));
	پیشفرض:
		logit_f("invalid type field");
		بازگشت (0);
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
ایستا صحیح
wtmp_write(ساختار logininfo *li, ساختار utmp *ut)
{
	ساختار stat buf;
	صحیح fd, ret = 1;

	اگر ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem writing %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		بازگشت (0);
	}
	اگر (fstat(fd, &buf) == 0)
		اگر (atomicio(vwrite, fd, ut, اندازه(*ut)) != اندازه(*ut)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMP_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);
	بازگشت (ret);
}

ایستا صحیح
wtmp_perform_login(ساختار logininfo *li)
{
	ساختار utmp ut;

	construct_utmp(li, &ut);
	بازگشت (wtmp_write(li, &ut));
}


ایستا صحیح
wtmp_perform_logout(ساختار logininfo *li)
{
	ساختار utmp ut;

	construct_utmp(li, &ut);
	بازگشت (wtmp_write(li, &ut));
}


صحیح
wtmp_write_entry(ساختار logininfo *li)
{
	انتخاب(li->type) {
	حالت LTYPE_LOGIN:
		بازگشت (wtmp_perform_login(li));
	حالت LTYPE_LOGOUT:
		بازگشت (wtmp_perform_logout(li));
	پیشفرض:
		logit_f("invalid type field");
		بازگشت (0);
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
ایستا صحیح
wtmp_islogin(ساختار logininfo *li, ساختار utmp *ut)
{
	اگر (strncmp(li->username, ut->ut_name,
	    MIN_SIZEOF(li->username, ut->ut_name)) == 0) {
# ifdef HAVE_TYPE_IN_UTMP
		اگر (ut->ut_type & USER_PROCESS)
			بازگشت (1);
# وگرنه
		بازگشت (1);
# endif
	}
	بازگشت (0);
}

صحیح
wtmp_get_entry(ساختار logininfo *li)
{
	ساختار stat st;
	ساختار utmp ut;
	صحیح fd, found = 0;

	/* Clear the time entries in our logininfo */
	li->tv_sec = li->tv_usec = 0;

	اگر ((fd = open(WTMP_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		بازگشت (0);
	}
	اگر (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		close(fd);
		بازگشت (0);
	}

	/* Seek to the start of the last struct utmp */
	اگر (lseek(fd, -(off_t)اندازه(ساختار utmp), SEEK_END) == -1) {
		/* Looks like we've got a fresh wtmp file */
		close(fd);
		بازگشت (0);
	}

	وقتی (!found) {
		اگر (atomicio(اقرأ, fd, &ut, اندازه(ut)) != اندازه(ut)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMP_FILE, strerror(errno));
			close (fd);
			بازگشت (0);
		}
		اگر (wtmp_islogin(li, &ut) ) {
			found = 1;
			/*
			 * We've already checked for a time in struct
			 * utmp, in login_getlast()
			 */
# ifdef HAVE_TIME_IN_UTMP
			li->tv_sec = ut.ut_time;
# وگرنه
#  اگر HAVE_TV_IN_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
# endif
			سطر_fullname(li->سطر, ut.ut_سطر,
			    MIN_SIZEOF(li->سطر, ut.ut_سطر));
# ifdef HAVE_HOST_IN_UTMP
			strlcpy(li->hostname, ut.ut_host,
			    MIN_SIZEOF(li->hostname, ut.ut_host));
# endif
			ادامه;
		}
		/* Seek back 2 x struct utmp */
		اگر (lseek(fd, -(off_t)(2 * اندازه(ساختار utmp)), SEEK_CUR) == -1) {
			/* We've found the start of the file, so quit */
			close(fd);
			بازگشت (0);
		}
	}

	/* We found an entry. Tidy up and return */
	close(fd);
	بازگشت (1);
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
ایستا صحیح
wtmpx_write(ساختار logininfo *li, ساختار utmpx *utx)
{
#ifndef HAVE_UPDWTMPX
	ساختار stat buf;
	صحیح fd, ret = 1;

	اگر ((fd = open(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		بازگشت (0);
	}

	اگر (fstat(fd, &buf) == 0)
		اگر (atomicio(vwrite, fd, utx, اندازه(*utx)) != اندازه(*utx)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);

	بازگشت (ret);
#وگرنه
	updwtmpx(WTMPX_FILE, utx);
	بازگشت (1);
#endif
}


ایستا صحیح
wtmpx_perform_login(ساختار logininfo *li)
{
	ساختار utmpx utx;

	construct_utmpx(li, &utx);
	بازگشت (wtmpx_write(li, &utx));
}


ایستا صحیح
wtmpx_perform_logout(ساختار logininfo *li)
{
	ساختار utmpx utx;

	construct_utmpx(li, &utx);
	بازگشت (wtmpx_write(li, &utx));
}


صحیح
wtmpx_write_entry(ساختار logininfo *li)
{
	انتخاب(li->type) {
	حالت LTYPE_LOGIN:
		بازگشت (wtmpx_perform_login(li));
	حالت LTYPE_LOGOUT:
		بازگشت (wtmpx_perform_logout(li));
	پیشفرض:
		logit_f("invalid type field");
		بازگشت (0);
	}
}

/* Please see the notes above wtmp_islogin() for information about the
   next two functions */

/* Return true if this wtmpx entry indicates a login */
ایستا صحیح
wtmpx_islogin(ساختار logininfo *li, ساختار utmpx *utx)
{
	اگر (strncmp(li->username, utx->ut_user,
	    MIN_SIZEOF(li->username, utx->ut_user)) == 0 ) {
# ifdef HAVE_TYPE_IN_UTMPX
		اگر (utx->ut_type == USER_PROCESS)
			بازگشت (1);
# وگرنه
		بازگشت (1);
# endif
	}
	بازگشت (0);
}


صحیح
wtmpx_get_entry(ساختار logininfo *li)
{
	ساختار stat st;
	ساختار utmpx utx;
	صحیح fd, found=0;

	/* Clear the time entries */
	li->tv_sec = li->tv_usec = 0;

	اگر ((fd = open(WTMPX_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		بازگشت (0);
	}
	اگر (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		close(fd);
		بازگشت (0);
	}

	/* Seek to the start of the last struct utmpx */
	اگر (lseek(fd, -(off_t)اندازه(ساختار utmpx), SEEK_END) == -1 ) {
		/* probably a newly rotated wtmpx file */
		close(fd);
		بازگشت (0);
	}

	وقتی (!found) {
		اگر (atomicio(اقرأ, fd, &utx, اندازه(utx)) != اندازه(utx)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			close (fd);
			بازگشت (0);
		}
		/*
		 * Logouts are recorded as a blank username on a particular
		 * line. So, we just need to find the username in struct utmpx
		 */
		اگر (wtmpx_islogin(li, &utx)) {
			found = 1;
# اگر defined(HAVE_TV_IN_UTMPX)
			li->tv_sec = utx.ut_tv.tv_sec;
# elif defined(HAVE_TIME_IN_UTMPX)
			li->tv_sec = utx.ut_time;
# endif
			سطر_fullname(li->سطر, utx.ut_سطر, اندازه(li->سطر));
# اگر defined(HAVE_HOST_IN_UTMPX)
			strlcpy(li->hostname, utx.ut_host,
			    MIN_SIZEOF(li->hostname, utx.ut_host));
# endif
			ادامه;
		}
		اگر (lseek(fd, -(off_t)(2 * اندازه(ساختار utmpx)), SEEK_CUR) == -1) {
			close(fd);
			بازگشت (0);
		}
	}

	close(fd);
	بازگشت (1);
}
#endif /* USE_WTMPX */

#ifdef USE_WTMPDB
ایستا صحیح
wtmpdb_perform_login(ساختار logininfo *li)
{
	uint64_t login_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	    li->tv_usec;
	ثابت نویسه *tty;

	اگر (strncmp(li->سطر, "/dev/", 5) == 0)
		tty = &(li->سطر[5]);
	وگرنه
		tty = li->سطر;

	li->wtmpdb_id = wtmpdb_login(پوچ, USER_PROCESS, li->username,
	    login_time, tty, li->hostname, 0, 0);

	اگر (li->wtmpdb_id < 0)
		بازگشت (0);

	بازگشت (1);
}

ایستا صحیح
wtmpdb_perform_logout(ساختار logininfo *li)
{
	uint64_t logout_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	   li->tv_usec;

	اگر (li->wtmpdb_id == 0) {
		ثابت نویسه *tty;

		اگر (strncmp(li->سطر, "/dev/", 5) == 0)
			tty = &(li->سطر[5]);
		وگرنه
			tty = li->سطر;

		li->wtmpdb_id = wtmpdb_get_id(پوچ, tty, پوچ);
	}
	wtmpdb_logout(پوچ, li->wtmpdb_id, logout_time, پوچ);

	بازگشت (1);
}

صحیح
wtmpdb_write_entry(ساختار logininfo *li)
{
	انتخاب(li->type) {
	حالت LTYPE_LOGIN:
		بازگشت (wtmpdb_perform_login(li));
	حالت LTYPE_LOGOUT:
		بازگشت (wtmpdb_perform_logout(li));
	پیشفرض:
		logit_f("invalid type field");
		بازگشت (0);
	}
}
#endif

/**
 ** Low-level libutil login() functions
 **/

#ifdef USE_LOGIN
ایستا صحیح
syslogin_perform_login(ساختار logininfo *li)
{
	ساختار utmp *ut;

	ut = xmalloc(اندازه(*ut));
	construct_utmp(li, ut);
	login(ut);
	آزاد(ut);

	بازگشت (1);
}

ایستا صحیح
syslogin_perform_logout(ساختار logininfo *li)
{
# ifdef HAVE_LOGOUT
	نویسه سطر[UT_LINESIZE];

	(تهی)سطر_stripname(سطر, li->سطر, اندازه(سطر));

	اگر (!logout(سطر))
		logit_f("logout() returned an error");
#  ifdef HAVE_LOGWTMP
	وگرنه
		logwtmp(سطر, "", "");
#  endif
	/* FIXME: (ATL - if the need arises) What to do if we have
	 * login, but no logout?  what if logout but no logwtmp? All
	 * routines are in libutil so they should all be there,
	 * but... */
# endif
	بازگشت (1);
}

صحیح
syslogin_write_entry(ساختار logininfo *li)
{
	انتخاب (li->type) {
	حالت LTYPE_LOGIN:
		بازگشت (syslogin_perform_login(li));
	حالت LTYPE_LOGOUT:
		بازگشت (syslogin_perform_logout(li));
	پیشفرض:
		logit_f("Invalid type field");
		بازگشت (0);
	}
}
#endif /* USE_LOGIN */

/* end of file log-syslogin.c */

/**
 ** Low-level lastlog functions
 **/

#ifdef USE_LASTLOG

#اگر !defined(LASTLOG_WRITE_PUTUTXLINE) || !defined(HAVE_GETLASTLOGXBYNAME)
/* open the file (using filemode) and seek to the login entry */
ایستا صحیح
lastlog_openseek(ساختار logininfo *li, صحیح *fd, صحیح filemode)
{
	off_t offset;
	نویسه lastlog_file[1024];
	ساختار stat st;

	اگر (stat(LASTLOG_FILE, &st) != 0) {
		logit("%s: Couldn't stat %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		بازگشت (0);
	}
	اگر (S_ISDIR(st.st_mode)) {
		snprintf(lastlog_file, اندازه(lastlog_file), "%s/%s",
		    LASTLOG_FILE, li->username);
	} وگرنه اگر (S_ISREG(st.st_mode)) {
		strlcpy(lastlog_file, LASTLOG_FILE, اندازه(lastlog_file));
	} وگرنه {
		logit("%s: %.100s is not a file or directory!", __func__,
		    LASTLOG_FILE);
		بازگشت (0);
	}

	*fd = open(lastlog_file, filemode, 0600);
	اگر (*fd < 0) {
		debug("%s: Couldn't open %s: %s", __func__,
		    lastlog_file, strerror(errno));
		بازگشت (0);
	}

	اگر (S_ISREG(st.st_mode)) {
		/* find this uid's offset in the lastlog file */
		offset = (off_t) ((u_long)li->uid * اندازه(ساختار lastlog));

		اگر (lseek(*fd, offset, SEEK_SET) != offset) {
			logit("%s: %s->lseek(): %s", __func__,
			    lastlog_file, strerror(errno));
			close(*fd);
			بازگشت (0);
		}
	}

	بازگشت (1);
}
#endif /* !LASTLOG_WRITE_PUTUTXLINE || !HAVE_GETLASTLOGXBYNAME */

#ifdef LASTLOG_WRITE_PUTUTXLINE
صحیح
lastlog_write_entry(ساختار logininfo *li)
{
	انتخاب(li->type) {
	حالت LTYPE_LOGIN:
		بازگشت 1; /* lastlog written by pututxline */
	پیشفرض:
		logit("lastlog_write_entry: Invalid type field");
		بازگشت 0;
	}
}
#وگرنه /* LASTLOG_WRITE_PUTUTXLINE */
صحیح
lastlog_write_entry(ساختار logininfo *li)
{
	ساختار lastlog last;
	صحیح fd;

	انتخاب(li->type) {
	حالت LTYPE_LOGIN:
		/* create our struct lastlog */
		memset(&last, '\0', اندازه(last));
		سطر_stripname(last.ll_سطر, li->سطر, اندازه(last.ll_سطر));
		strlcpy(last.ll_host, li->hostname,
		    MIN_SIZEOF(last.ll_host, li->hostname));
		last.ll_time = li->tv_sec;

		اگر (!lastlog_openseek(li, &fd, O_RDWR|O_CREAT))
			بازگشت (0);

		/* write the entry */
		اگر (atomicio(vwrite, fd, &last, اندازه(last)) != اندازه(last)) {
			close(fd);
			logit("%s: Error writing to %s: %s", __func__,
			    LASTLOG_FILE, strerror(errno));
			بازگشت (0);
		}

		close(fd);
		بازگشت (1);
	پیشفرض:
		logit_f("Invalid type field");
		بازگشت (0);
	}
}
#endif /* LASTLOG_WRITE_PUTUTXLINE */

#ifdef HAVE_GETLASTLOGXBYNAME
صحیح
lastlog_get_entry(ساختار logininfo *li)
{
	ساختار lastlogx l, *ll;

	اگر ((ll = getlastlogxbyname(li->username, &l)) == پوچ) {
		memset(&l, '\0', اندازه(l));
		ll = &l;
	}
	سطر_fullname(li->سطر, ll->ll_سطر, اندازه(li->سطر));
	strlcpy(li->hostname, ll->ll_host,
		MIN_SIZEOF(li->hostname, ll->ll_host));
	li->tv_sec = ll->ll_tv.tv_sec;
	li->tv_usec = ll->ll_tv.tv_usec;
	بازگشت (1);
}
#وگرنه /* HAVE_GETLASTLOGXBYNAME */
صحیح
lastlog_get_entry(ساختار logininfo *li)
{
	ساختار lastlog last;
	صحیح fd, ret;

	اگر (!lastlog_openseek(li, &fd, O_RDONLY))
		بازگشت (0);

	ret = atomicio(اقرأ, fd, &last, اندازه(last));
	close(fd);

	انتخاب (ret) {
	حالت 0:
		memset(&last, '\0', اندازه(last));
		/* FALLTHRU */
	حالت اندازه(last):
		سطر_fullname(li->سطر, last.ll_سطر, اندازه(li->سطر));
		strlcpy(li->hostname, last.ll_host,
		    MIN_SIZEOF(li->hostname, last.ll_host));
		li->tv_sec = last.ll_time;
		بازگشت (1);
	حالت -1:
		error("%s: Error reading from %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		بازگشت (0);
	پیشفرض:
		error("%s: Error reading from %s: Expecting %d, got %d",
		    __func__, LASTLOG_FILE, (صحیح)اندازه(last), ret);
		بازگشت (0);
	}

	/* NOTREACHED */
	بازگشت (0);
}
#endif /* HAVE_GETLASTLOGXBYNAME */
#endif /* USE_LASTLOG */

#اگر defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
صحیح
utmpx_get_entry(ساختار logininfo *li)
{
	ساختار utmpx *utx;

	اگر (setutxdb(UTXDB_LASTLOGIN, پوچ) != 0)
		بازگشت (0);
	utx = getutxuser(li->username);
	اگر (utx == پوچ) {
		endutxent();
		بازگشت (0);
	}

	سطر_fullname(li->سطر, utx->ut_سطر,
	    MIN_SIZEOF(li->سطر, utx->ut_سطر));
	strlcpy(li->hostname, utx->ut_host,
	    MIN_SIZEOF(li->hostname, utx->ut_host));
	li->tv_sec = utx->ut_tv.tv_sec;
	li->tv_usec = utx->ut_tv.tv_usec;
	endutxent();
	بازگشت (1);
}
#endif /* USE_UTMPX && HAVE_SETUTXDB && UTXDB_LASTLOGIN && HAVE_GETUTXUSER */

#ifdef USE_BTMP
/*
 * Logs failed login attempts in _PATH_BTMP if that exists.
 * The most common login failure is to give password instead of username.
 * So the _PATH_BTMP file is checked for the correct permission, so that only
 * root can read it.
 */
تهی
record_failed_login(ساختار ssh *ssh, ثابت نویسه *username, ثابت نویسه *hostname,
    ثابت نویسه *ttyn)
{
	صحیح fd;
	ساختار utmp ut;
	ساختار logininfo li;
	socklen_t fromlen = اندازه(li.hostaddr);
	time_t t;
	ساختار stat fst;

	اگر (geteuid() != 0)
		بازگشت;
	اگر ((fd = open(_PATH_BTMP, O_WRONLY | O_APPEND)) < 0) {
		debug("Unable to open the btmp file %s: %s", _PATH_BTMP,
		    strerror(errno));
		بازگشت;
	}
	اگر (fstat(fd, &fst) < 0) {
		logit("%s: fstat of %s failed: %s", __func__, _PATH_BTMP,
		    strerror(errno));
		برو out;
	}
	اگر ((fst.st_mode & (S_IXGRP | S_IRWXO)) || fst.st_uid != 0) {
		logit("Excess permission or bad ownership on file %s",
		    _PATH_BTMP);
		برو out;
	}

	/* Construct a logininfo and turn it into a utmp */
	memset(&li, 0, اندازه(li));
	li.type = LTYPE_FAILED;
	li.pid = getpid();
	strlcpy(li.سطر, "ssh:notty", اندازه(li.سطر));
	strlcpy(li.username, username, اندازه(li.username));
	strlcpy(li.hostname, hostname, اندازه(li.hostname));
	time(&t);
	li.tv_sec = t > 0 ? (unsigned long)t : 0;
	اگر (ssh_packet_connection_is_on_socket(ssh)) {
		(تهی)getpeername(ssh_packet_get_connection_in(ssh),
		    &li.hostaddr.sa, &fromlen);
	}
	construct_utmp(&li, &ut);

	اگر (atomicio(vwrite, fd, &ut, اندازه(ut)) != اندازه(ut)) {
		error("Failed to write to %s: %s", _PATH_BTMP,
		    strerror(errno));
	}
out:
	close(fd);
}
#endif	/* USE_BTMP */
