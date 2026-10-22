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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/time.h>

#અન્તર્ભાવ <netinet/in.h>

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "loginrec.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "misc.h"

# include <util.h>

#ifdef USE_WTMPDB
# include <wtmpdb.h>
#endif

/**
 ** prototypes for helper functions in this file
 **/

#જો HAVE_UTMP_H
શૂન્ય set_utmp_time(સંરચના logininfo *li, સંરચના utmp *ut);
શૂન્ય construct_utmp(સંરચના logininfo *li, સંરચના utmp *ut);
#endif

#ifdef HAVE_UTMPX_H
શૂન્ય set_utmpx_time(સંરચના logininfo *li, સંરચના utmpx *ut);
શૂન્ય construct_utmpx(સંરચના logininfo *li, સંરચના utmpx *ut);
#endif

પૂર્ણાંક utmp_write_entry(સંરચના logininfo *li);
પૂર્ણાંક utmpx_write_entry(સંરચના logininfo *li);
પૂર્ણાંક wtmp_write_entry(સંરચના logininfo *li);
પૂર્ણાંક wtmpx_write_entry(સંરચના logininfo *li);
પૂર્ણાંક lastlog_write_entry(સંરચના logininfo *li);
પૂર્ણાંક syslogin_write_entry(સંરચના logininfo *li);
#ifdef USE_WTMPDB
પૂર્ણાંક wtmpdb_write_entry(સંરચના logininfo *li);
#endif

પૂર્ણાંક getlast_entry(સંરચના logininfo *li);
પૂર્ણાંક lastlog_get_entry(સંરચના logininfo *li);
પૂર્ણાંક utmpx_get_entry(સંરચના logininfo *li);
પૂર્ણાંક wtmp_get_entry(સંરચના logininfo *li);
પૂર્ણાંક wtmpx_get_entry(સંરચના logininfo *li);

બાહ્ય સંરચના sshbuf *loginmsg;

/* pick the shortest string */
#define MIN_SIZEOF(s1,s2) (કદ(s1) < કદ(s2) ? કદ(s1) : કદ(s2))

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
પૂર્ણાંક
login_login(સંરચના logininfo *li)
{
	li->type = LTYPE_LOGIN;
	પાછા (login_write(li));
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
પૂર્ણાંક
login_logout(સંરચના logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	પાછા (login_write(li));
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
unsigned પૂર્ણાંક
login_get_lastlog_time(અચલ uid_t uid)
{
	સંરચના logininfo li;

	જો (login_get_lastlog(&li, uid))
		પાછા (li.tv_sec);
	નહીંતર
		પાછા (0);
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
સંરચના logininfo *
login_get_lastlog(સંરચના logininfo *li, અચલ uid_t uid)
{
	સંરચના passwd *pw;

	memset(li, '\0', કદ(*li));
	li->uid = uid;

	/*
	 * If we don't have a 'real' lastlog, we need the username to
	 * reliably search wtmp(x) for the last login (see
	 * wtmp_get_entry().)
	 */
	pw = getpwuid(uid);
	જો (pw == ખાલી)
		fatal("%s: Cannot find account for uid %ld", __func__,
		    (long)uid);

	જો (strlcpy(li->username, pw->pw_name, કદ(li->username)) >=
	    કદ(li->username)) {
		error("%s: username too long (%lu > max %lu)", __func__,
		    (unsigned long)strlen(pw->pw_name),
		    (unsigned long)કદ(li->username) - 1);
		પાછા ખાલી;
	}

	જો (getlast_entry(li))
		પાછા (li);
	નહીંતર
		પાછા (ખાલી);
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
સંરચના
logininfo *login_alloc_entry(pid_t pid, અચલ અક્ષર *username,
    અચલ અક્ષર *hostname, અચલ અક્ષર *લીટી)
{
	સંરચના logininfo *newli;

	newli = xmalloc(કદ(*newli));
	login_init_entry(newli, pid, username, hostname, લીટી);
	પાછા (newli);
}


/* login_free_entry(struct logininfo *)    - free struct memory */
શૂન્ય
login_free_entry(સંરચના logininfo *li)
{
	મુક્ત(li);
}


/* login_init_entry(struct logininfo *, int, char*, char*, char*)
 *                                        - initialise a struct logininfo
 *
 * Populates a new struct logininfo, a data structure meant to carry
 * the information required to portably record login info.
 *
 * Returns: 1
 */
પૂર્ણાંક
login_init_entry(સંરચના logininfo *li, pid_t pid, અચલ અક્ષર *username,
    અચલ અક્ષર *hostname, અચલ અક્ષર *લીટી)
{
	સંરચના passwd *pw;

	memset(li, 0, કદ(*li));

	li->pid = pid;

	/* set the line information */
	જો (લીટી)
		લીટી_fullname(li->લીટી, લીટી, કદ(li->લીટી));

	જો (username) {
		strlcpy(li->username, username, કદ(li->username));
		pw = getpwnam(li->username);
		જો (pw == ખાલી) {
			fatal("%s: Cannot find user \"%s\"", __func__,
			    li->username);
		}
		li->uid = pw->pw_uid;
	}

	જો (hostname)
		strlcpy(li->hostname, hostname, કદ(li->hostname));

	પાછા (1);
}

/*
 * login_set_current_time(struct logininfo *)    - set the current time
 *
 * Set the current time in a logininfo structure. This function is
 * meant to eliminate the need to deal with system dependencies for
 * time handling.
 */
શૂન્ય
login_set_current_time(સંરચના logininfo *li)
{
	સંરચના timeval tv;

	gettimeofday(&tv, ખાલી);

	li->tv_sec = tv.tv_sec;
	li->tv_usec = tv.tv_usec;
}

/* copy a sockaddr_* into our logininfo */
શૂન્ય
login_set_addr(સંરચના logininfo *li, અચલ સંરચના sockaddr *sa,
    અચલ unsigned પૂર્ણાંક sa_size)
{
	unsigned પૂર્ણાંક bufsize = sa_size;

	/* make sure we don't overrun our union */
	જો (કદ(li->hostaddr) < sa_size)
		bufsize = કદ(li->hostaddr);

	memcpy(&li->hostaddr.sa, sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/
પૂર્ણાંક
login_write(સંરચના logininfo *li)
{
#ifndef HAVE_CYGWIN
	જો (geteuid() != 0) {
		logit("Attempt to write login records by non-root user (aborting)");
		પાછા (1);
	}
#endif

	/* set the timestamp */
	login_set_current_time(li);
#ifdef USE_LOGIN
	syslogin_write_entry(li);
#endif
#ifdef USE_LASTLOG
	જો (li->type == LTYPE_LOGIN)
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
	જો (li->type == LTYPE_LOGIN &&
	    !sys_auth_record_login(li->username,li->hostname,li->લીટી,
	    loginmsg))
		logit("Writing login record failed for %s", li->username);
#endif
#ifdef SSH_AUDIT_EVENTS
	જો (li->type == LTYPE_LOGIN)
		audit_session_open(li);
	નહીંતર જો (li->type == LTYPE_LOGOUT)
		audit_session_close(li);
#endif
	પાછા (0);
}

#ifdef LOGIN_NEEDS_UTMPX
પૂર્ણાંક
login_utmp_only(સંરચના logininfo *li)
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
	પાછા (0);
}
#endif

/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
પૂર્ણાંક
getlast_entry(સંરચના logininfo *li)
{
#ifdef USE_LASTLOG
	પાછા(lastlog_get_entry(li));
#નહીંતર /* !USE_LASTLOG */
#જો defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
	પાછા (utmpx_get_entry(li));
#endif

#જો defined(DISABLE_LASTLOG)
	/* On some systems we shouldn't even try to obtain last login
	 * time, e.g. AIX */
	પાછા (0);
# elif defined(USE_WTMP) && \
    (defined(HAVE_TIME_IN_UTMP) || defined(HAVE_TV_IN_UTMP))
	/* retrieve last login time from utmp */
	પાછા (wtmp_get_entry(li));
# elif defined(USE_WTMPX) && \
    (defined(HAVE_TIME_IN_UTMPX) || defined(HAVE_TV_IN_UTMPX))
	/* If wtmp isn't available, try wtmpx */
	પાછા (wtmpx_get_entry(li));
# નહીંતર
	/* Give up: No means of retrieving last login time */
	પાછા (0);
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
અક્ષર *
લીટી_fullname(અક્ષર *dst, અચલ અક્ષર *src, u_int dstsize)
{
	memset(dst, '\0', dstsize);
	જો ((strncmp(src, "/dev/", 5) == 0) || (dstsize < (strlen(src) + 5)))
		strlcpy(dst, src, dstsize);
	નહીંતર {
		strlcpy(dst, "/dev/", dstsize);
		strlcat(dst, src, dstsize);
	}
	પાછા (dst);
}

/* line_stripname(): strip the leading '/dev' if it exists, return dst */
અક્ષર *
લીટી_stripname(અક્ષર *dst, અચલ અક્ષર *src, પૂર્ણાંક dstsize)
{
	memset(dst, '\0', dstsize);
	જો (strncmp(src, "/dev/", 5) == 0)
		strlcpy(dst, src + 5, dstsize);
	નહીંતર
		strlcpy(dst, src, dstsize);
	પાછા (dst);
}

/*
 * line_abbrevname(): Return the abbreviated (usually four-character)
 * form of the line (Just use the last <dstsize> characters of the
 * full name.)
 *
 * NOTE: use strncpy because we do NOT necessarily want zero
 * termination
 */
અક્ષર *
લીટી_abbrevname(અક્ષર *dst, અચલ અક્ષર *src, પૂર્ણાંક dstsize)
{
	size_t len;

	memset(dst, '\0', dstsize);

	જો (strcmp(src, "ssh:notty") == 0)
		પાછા dst;

	/* Always skip prefix if present */
	જો (strncmp(src, "/dev/", 5) == 0)
		src += 5;

#ifdef WITH_ABBREV_NO_TTY
	જો (strncmp(src, "tty", 3) == 0)
		src += 3;
#endif

	len = strlen(src);

	જો (len > 0) {
		જો (((પૂર્ણાંક)len - dstsize) > 0)
			src +=  ((પૂર્ણાંક)len - dstsize);

		/* note: _don't_ change this to strlcpy */
		strncpy(dst, src, (size_t)dstsize);
	}

	પાછા (dst);
}

/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#જો defined(USE_BTMP) || defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
શૂન્ય
set_utmp_time(સંરચના logininfo *li, સંરચના utmp *ut)
{
# જો defined(HAVE_TV_IN_UTMP)
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMP)
	ut->ut_time = li->tv_sec;
# endif
}

શૂન્ય
construct_utmp(સંરચના logininfo *li,
		    સંરચના utmp *ut)
{
# ifdef HAVE_ADDR_V6_IN_UTMP
	સંરચના sockaddr_in6 *sa6;
# endif

	memset(ut, '\0', કદ(*ut));

	/* First fill out fields used for both logins and logouts */

# ifdef HAVE_ID_IN_UTMP
	લીટી_abbrevname(ut->ut_id, li->લીટી, કદ(ut->ut_id));
# endif

# ifdef HAVE_TYPE_IN_UTMP
	/* This is done here to keep utmp constants out of struct logininfo */
	પસંદગી (li->type) {
	સ્થિતિ LTYPE_FAILED:
		ut->ut_type = LOGIN_PROCESS;
		તોડો;
	સ્થિતિ LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		તોડો;
	સ્થિતિ LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		તોડો;
	}
# endif
	set_utmp_time(li, ut);

	લીટી_stripname(ut->ut_લીટી, li->લીટી, કદ(ut->ut_લીટી));

# ifdef HAVE_PID_IN_UTMP
	ut->ut_pid = li->pid;
# endif

	/* If we're logging out, leave all other fields blank */
	જો (li->type == LTYPE_LOGOUT)
		પાછા;

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
	જો (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMP
	/* this is just a 128-bit IPv6 address */
	જો (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((સંરચના sockaddr_in6 *)&li->hostaddr.sa);
		memcpy(ut->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		જો (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
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

#જો defined(USE_UTMPX) || defined (USE_WTMPX)
/* build the utmpx structure */
શૂન્ય
set_utmpx_time(સંરચના logininfo *li, સંરચના utmpx *utx)
{
# જો defined(HAVE_TV_IN_UTMPX)
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMPX)
	utx->ut_time = li->tv_sec;
# endif
}

શૂન્ય
construct_utmpx(સંરચના logininfo *li, સંરચના utmpx *utx)
{
# ifdef HAVE_ADDR_V6_IN_UTMPX
	સંરચના sockaddr_in6 *sa6;
#  endif
	memset(utx, '\0', કદ(*utx));

# ifdef HAVE_ID_IN_UTMPX
	લીટી_abbrevname(utx->ut_id, li->લીટી, કદ(utx->ut_id));
# endif

	/* this is done here to keep utmp constants out of loginrec.h */
	પસંદગી (li->type) {
	સ્થિતિ LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		તોડો;
	સ્થિતિ LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		તોડો;
	}
	લીટી_stripname(utx->ut_લીટી, li->લીટી, કદ(utx->ut_લીટી));
	set_utmpx_time(li, utx);
	utx->ut_pid = li->pid;

	/* strncpy(): Don't necessarily want null termination */
	strncpy(utx->ut_user, li->username,
	    MIN_SIZEOF(utx->ut_user, li->username));

	જો (li->type == LTYPE_LOGOUT)
		પાછા;

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
	જો (li->hostaddr.sa.sa_family == AF_INET)
		utx->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMPX
	/* this is just a 128-bit IPv6 address */
	જો (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((સંરચના sockaddr_in6 *)&li->hostaddr.sa);
		memcpy(utx->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		જો (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			utx->ut_addr_v6[0] = utx->ut_addr_v6[3];
			utx->ut_addr_v6[1] = 0;
			utx->ut_addr_v6[2] = 0;
			utx->ut_addr_v6[3] = 0;
		}
	}
# endif
# ifdef HAVE_SYSLEN_IN_UTMPX
	/* ut_syslen is the length of the utx_host string */
	utx->ut_syslen = MINIMUM(strlen(li->hostname), કદ(utx->ut_host));
# endif
}
#endif /* USE_UTMPX || USE_WTMPX */

/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */
#ifdef USE_UTMP

/* if we can, use pututline() etc. */
# જો !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
	defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
# endif


/* write a utmp entry with the system's help (pututline() and pals) */
# ifdef UTMP_USE_LIBRARY
સ્થિર પૂર્ણાંક
utmp_write_library(સંરચના logininfo *li, સંરચના utmp *ut)
{
	setutent();
	pututline(ut);
#  ifdef HAVE_ENDUTENT
	endutent();
#  endif
	પાછા (1);
}
# નહીંતર /* UTMP_USE_LIBRARY */

/*
 * Write a utmp entry direct to the file
 * This is a slightly modification of code in OpenBSD's login.c
 */
સ્થિર પૂર્ણાંક
utmp_write_direct(સંરચના logininfo *li, સંરચના utmp *ut)
{
	સંરચના utmp old_ut;
	નોંધણી પૂર્ણાંક fd;
	પૂર્ણાંક tty;

	/* FIXME: (ATL) ttyslot() needs local implementation */

#જો defined(HAVE_GETTTYENT)
	સંરચના ttyent *ty;

	tty=0;
	setttyent();
	જ્યારે (ખાલી != (ty = getttyent())) {
		tty++;
		જો (!strncmp(ty->ty_name, ut->ut_લીટી, કદ(ut->ut_લીટી)))
			તોડો;
	}
	endttyent();

	જો (ખાલી == ty) {
		logit_f("tty not found");
		પાછા (0);
	}
#નહીંતર /* FIXME */

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

#endif /* HAVE_GETTTYENT */

	જો (tty > 0 && (fd = open(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		off_t pos, ret;

		pos = (off_t)tty * કદ(સંરચના utmp);
		જો ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			પાછા (0);
		}
		જો (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			પાછા (0);
		}
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		જો (atomicio(પઠ, fd, &old_ut, કદ(old_ut)) == કદ(old_ut) &&
		    (ut->ut_host[0] == '\0') && (old_ut.ut_host[0] != '\0') &&
		    (strncmp(old_ut.ut_લીટી, ut->ut_લીટી, કદ(ut->ut_લીટી)) == 0) &&
		    (strncmp(old_ut.ut_name, ut->ut_name, કદ(ut->ut_name)) == 0))
			memcpy(ut->ut_host, old_ut.ut_host, કદ(ut->ut_host));

		જો ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			પાછા (0);
		}
		જો (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			પાછા (0);
		}
		જો (atomicio(vwrite, fd, ut, કદ(*ut)) != કદ(*ut)) {
			logit("%s: error writing %s: %s", __func__,
			    UTMP_FILE, strerror(errno));
			close(fd);
			પાછા (0);
		}

		close(fd);
		પાછા (1);
	} નહીંતર {
		પાછા (0);
	}
}
# endif /* UTMP_USE_LIBRARY */

સ્થિર પૂર્ણાંક
utmp_perform_login(સંરચના logininfo *li)
{
	સંરચના utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	જો (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		પાછા (0);
	}
# નહીંતર
	જો (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		પાછા (0);
	}
# endif
	પાછા (1);
}


સ્થિર પૂર્ણાંક
utmp_perform_logout(સંરચના logininfo *li)
{
	સંરચના utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	જો (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		પાછા (0);
	}
# નહીંતર
	જો (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		પાછા (0);
	}
# endif
	પાછા (1);
}


પૂર્ણાંક
utmp_write_entry(સંરચના logininfo *li)
{
	પસંદગી(li->type) {
	સ્થિતિ LTYPE_LOGIN:
		પાછા (utmp_perform_login(li));

	સ્થિતિ LTYPE_LOGOUT:
		પાછા (utmp_perform_logout(li));

	મૂળભૂત:
		logit_f("invalid type field");
		પાછા (0);
	}
}
#endif /* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#ifdef USE_UTMPX

/* if we have the wherewithal, use pututxline etc. */
# જો !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) && \
	defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
# endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
# ifdef UTMPX_USE_LIBRARY
સ્થિર પૂર્ણાંક
utmpx_write_library(સંરચના logininfo *li, સંરચના utmpx *utx)
{
	setutxent();
	pututxline(utx);

#  ifdef HAVE_ENDUTXENT
	endutxent();
#  endif
	પાછા (1);
}

# નહીંતર /* UTMPX_USE_LIBRARY */

/* write a utmp entry direct to the file */
સ્થિર પૂર્ણાંક
utmpx_write_direct(સંરચના logininfo *li, સંરચના utmpx *utx)
{
	logit_f("not implemented!");
	પાછા (0);
}
# endif /* UTMPX_USE_LIBRARY */

સ્થિર પૂર્ણાંક
utmpx_perform_login(સંરચના logininfo *li)
{
	સંરચના utmpx utx;

	construct_utmpx(li, &utx);
# ifdef UTMPX_USE_LIBRARY
	જો (!utmpx_write_library(li, &utx)) {
		logit_f("utmp_write_library() failed");
		પાછા (0);
	}
# નહીંતર
	જો (!utmpx_write_direct(li, &utx)) {
		logit_f("utmp_write_direct() failed");
		પાછા (0);
	}
# endif
	પાછા (1);
}


સ્થિર પૂર્ણાંક
utmpx_perform_logout(સંરચના logininfo *li)
{
	સંરચના utmpx utx;

	construct_utmpx(li, &utx);
# ifdef HAVE_ID_IN_UTMPX
	લીટી_abbrevname(utx.ut_id, li->લીટી, કદ(utx.ut_id));
# endif
# ifdef HAVE_TYPE_IN_UTMPX
	utx.ut_type = DEAD_PROCESS;
# endif

# ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
# નહીંતર
	utmpx_write_direct(li, &utx);
# endif
	પાછા (1);
}

પૂર્ણાંક
utmpx_write_entry(સંરચના logininfo *li)
{
	પસંદગી(li->type) {
	સ્થિતિ LTYPE_LOGIN:
		પાછા (utmpx_perform_login(li));
	સ્થિતિ LTYPE_LOGOUT:
		પાછા (utmpx_perform_logout(li));
	મૂળભૂત:
		logit_f("invalid type field");
		પાછા (0);
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
સ્થિર પૂર્ણાંક
wtmp_write(સંરચના logininfo *li, સંરચના utmp *ut)
{
	સંરચના stat buf;
	પૂર્ણાંક fd, ret = 1;

	જો ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem writing %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		પાછા (0);
	}
	જો (fstat(fd, &buf) == 0)
		જો (atomicio(vwrite, fd, ut, કદ(*ut)) != કદ(*ut)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMP_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);
	પાછા (ret);
}

સ્થિર પૂર્ણાંક
wtmp_perform_login(સંરચના logininfo *li)
{
	સંરચના utmp ut;

	construct_utmp(li, &ut);
	પાછા (wtmp_write(li, &ut));
}


સ્થિર પૂર્ણાંક
wtmp_perform_logout(સંરચના logininfo *li)
{
	સંરચના utmp ut;

	construct_utmp(li, &ut);
	પાછા (wtmp_write(li, &ut));
}


પૂર્ણાંક
wtmp_write_entry(સંરચના logininfo *li)
{
	પસંદગી(li->type) {
	સ્થિતિ LTYPE_LOGIN:
		પાછા (wtmp_perform_login(li));
	સ્થિતિ LTYPE_LOGOUT:
		પાછા (wtmp_perform_logout(li));
	મૂળભૂત:
		logit_f("invalid type field");
		પાછા (0);
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
સ્થિર પૂર્ણાંક
wtmp_islogin(સંરચના logininfo *li, સંરચના utmp *ut)
{
	જો (strncmp(li->username, ut->ut_name,
	    MIN_SIZEOF(li->username, ut->ut_name)) == 0) {
# ifdef HAVE_TYPE_IN_UTMP
		જો (ut->ut_type & USER_PROCESS)
			પાછા (1);
# નહીંતર
		પાછા (1);
# endif
	}
	પાછા (0);
}

પૂર્ણાંક
wtmp_get_entry(સંરચના logininfo *li)
{
	સંરચના stat st;
	સંરચના utmp ut;
	પૂર્ણાંક fd, found = 0;

	/* Clear the time entries in our logininfo */
	li->tv_sec = li->tv_usec = 0;

	જો ((fd = open(WTMP_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		પાછા (0);
	}
	જો (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		close(fd);
		પાછા (0);
	}

	/* Seek to the start of the last struct utmp */
	જો (lseek(fd, -(off_t)કદ(સંરચના utmp), SEEK_END) == -1) {
		/* Looks like we've got a fresh wtmp file */
		close(fd);
		પાછા (0);
	}

	જ્યારે (!found) {
		જો (atomicio(પઠ, fd, &ut, કદ(ut)) != કદ(ut)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMP_FILE, strerror(errno));
			close (fd);
			પાછા (0);
		}
		જો (wtmp_islogin(li, &ut) ) {
			found = 1;
			/*
			 * We've already checked for a time in struct
			 * utmp, in login_getlast()
			 */
# ifdef HAVE_TIME_IN_UTMP
			li->tv_sec = ut.ut_time;
# નહીંતર
#  જો HAVE_TV_IN_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
# endif
			લીટી_fullname(li->લીટી, ut.ut_લીટી,
			    MIN_SIZEOF(li->લીટી, ut.ut_લીટી));
# ifdef HAVE_HOST_IN_UTMP
			strlcpy(li->hostname, ut.ut_host,
			    MIN_SIZEOF(li->hostname, ut.ut_host));
# endif
			ચાલુ;
		}
		/* Seek back 2 x struct utmp */
		જો (lseek(fd, -(off_t)(2 * કદ(સંરચના utmp)), SEEK_CUR) == -1) {
			/* We've found the start of the file, so quit */
			close(fd);
			પાછા (0);
		}
	}

	/* We found an entry. Tidy up and return */
	close(fd);
	પાછા (1);
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
સ્થિર પૂર્ણાંક
wtmpx_write(સંરચના logininfo *li, સંરચના utmpx *utx)
{
#ifndef HAVE_UPDWTMPX
	સંરચના stat buf;
	પૂર્ણાંક fd, ret = 1;

	જો ((fd = open(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		પાછા (0);
	}

	જો (fstat(fd, &buf) == 0)
		જો (atomicio(vwrite, fd, utx, કદ(*utx)) != કદ(*utx)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);

	પાછા (ret);
#નહીંતર
	updwtmpx(WTMPX_FILE, utx);
	પાછા (1);
#endif
}


સ્થિર પૂર્ણાંક
wtmpx_perform_login(સંરચના logininfo *li)
{
	સંરચના utmpx utx;

	construct_utmpx(li, &utx);
	પાછા (wtmpx_write(li, &utx));
}


સ્થિર પૂર્ણાંક
wtmpx_perform_logout(સંરચના logininfo *li)
{
	સંરચના utmpx utx;

	construct_utmpx(li, &utx);
	પાછા (wtmpx_write(li, &utx));
}


પૂર્ણાંક
wtmpx_write_entry(સંરચના logininfo *li)
{
	પસંદગી(li->type) {
	સ્થિતિ LTYPE_LOGIN:
		પાછા (wtmpx_perform_login(li));
	સ્થિતિ LTYPE_LOGOUT:
		પાછા (wtmpx_perform_logout(li));
	મૂળભૂત:
		logit_f("invalid type field");
		પાછા (0);
	}
}

/* Please see the notes above wtmp_islogin() for information about the
   next two functions */

/* Return true if this wtmpx entry indicates a login */
સ્થિર પૂર્ણાંક
wtmpx_islogin(સંરચના logininfo *li, સંરચના utmpx *utx)
{
	જો (strncmp(li->username, utx->ut_user,
	    MIN_SIZEOF(li->username, utx->ut_user)) == 0 ) {
# ifdef HAVE_TYPE_IN_UTMPX
		જો (utx->ut_type == USER_PROCESS)
			પાછા (1);
# નહીંતર
		પાછા (1);
# endif
	}
	પાછા (0);
}


પૂર્ણાંક
wtmpx_get_entry(સંરચના logininfo *li)
{
	સંરચના stat st;
	સંરચના utmpx utx;
	પૂર્ણાંક fd, found=0;

	/* Clear the time entries */
	li->tv_sec = li->tv_usec = 0;

	જો ((fd = open(WTMPX_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		પાછા (0);
	}
	જો (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		close(fd);
		પાછા (0);
	}

	/* Seek to the start of the last struct utmpx */
	જો (lseek(fd, -(off_t)કદ(સંરચના utmpx), SEEK_END) == -1 ) {
		/* probably a newly rotated wtmpx file */
		close(fd);
		પાછા (0);
	}

	જ્યારે (!found) {
		જો (atomicio(પઠ, fd, &utx, કદ(utx)) != કદ(utx)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			close (fd);
			પાછા (0);
		}
		/*
		 * Logouts are recorded as a blank username on a particular
		 * line. So, we just need to find the username in struct utmpx
		 */
		જો (wtmpx_islogin(li, &utx)) {
			found = 1;
# જો defined(HAVE_TV_IN_UTMPX)
			li->tv_sec = utx.ut_tv.tv_sec;
# elif defined(HAVE_TIME_IN_UTMPX)
			li->tv_sec = utx.ut_time;
# endif
			લીટી_fullname(li->લીટી, utx.ut_લીટી, કદ(li->લીટી));
# જો defined(HAVE_HOST_IN_UTMPX)
			strlcpy(li->hostname, utx.ut_host,
			    MIN_SIZEOF(li->hostname, utx.ut_host));
# endif
			ચાલુ;
		}
		જો (lseek(fd, -(off_t)(2 * કદ(સંરચના utmpx)), SEEK_CUR) == -1) {
			close(fd);
			પાછા (0);
		}
	}

	close(fd);
	પાછા (1);
}
#endif /* USE_WTMPX */

#ifdef USE_WTMPDB
સ્થિર પૂર્ણાંક
wtmpdb_perform_login(સંરચના logininfo *li)
{
	uint64_t login_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	    li->tv_usec;
	અચલ અક્ષર *tty;

	જો (strncmp(li->લીટી, "/dev/", 5) == 0)
		tty = &(li->લીટી[5]);
	નહીંતર
		tty = li->લીટી;

	li->wtmpdb_id = wtmpdb_login(ખાલી, USER_PROCESS, li->username,
	    login_time, tty, li->hostname, 0, 0);

	જો (li->wtmpdb_id < 0)
		પાછા (0);

	પાછા (1);
}

સ્થિર પૂર્ણાંક
wtmpdb_perform_logout(સંરચના logininfo *li)
{
	uint64_t logout_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	   li->tv_usec;

	જો (li->wtmpdb_id == 0) {
		અચલ અક્ષર *tty;

		જો (strncmp(li->લીટી, "/dev/", 5) == 0)
			tty = &(li->લીટી[5]);
		નહીંતર
			tty = li->લીટી;

		li->wtmpdb_id = wtmpdb_get_id(ખાલી, tty, ખાલી);
	}
	wtmpdb_logout(ખાલી, li->wtmpdb_id, logout_time, ખાલી);

	પાછા (1);
}

પૂર્ણાંક
wtmpdb_write_entry(સંરચના logininfo *li)
{
	પસંદગી(li->type) {
	સ્થિતિ LTYPE_LOGIN:
		પાછા (wtmpdb_perform_login(li));
	સ્થિતિ LTYPE_LOGOUT:
		પાછા (wtmpdb_perform_logout(li));
	મૂળભૂત:
		logit_f("invalid type field");
		પાછા (0);
	}
}
#endif

/**
 ** Low-level libutil login() functions
 **/

#ifdef USE_LOGIN
સ્થિર પૂર્ણાંક
syslogin_perform_login(સંરચના logininfo *li)
{
	સંરચના utmp *ut;

	ut = xmalloc(કદ(*ut));
	construct_utmp(li, ut);
	login(ut);
	મુક્ત(ut);

	પાછા (1);
}

સ્થિર પૂર્ણાંક
syslogin_perform_logout(સંરચના logininfo *li)
{
# ifdef HAVE_LOGOUT
	અક્ષર લીટી[UT_LINESIZE];

	(શૂન્ય)લીટી_stripname(લીટી, li->લીટી, કદ(લીટી));

	જો (!logout(લીટી))
		logit_f("logout() returned an error");
#  ifdef HAVE_LOGWTMP
	નહીંતર
		logwtmp(લીટી, "", "");
#  endif
	/* FIXME: (ATL - if the need arises) What to do if we have
	 * login, but no logout?  what if logout but no logwtmp? All
	 * routines are in libutil so they should all be there,
	 * but... */
# endif
	પાછા (1);
}

પૂર્ણાંક
syslogin_write_entry(સંરચના logininfo *li)
{
	પસંદગી (li->type) {
	સ્થિતિ LTYPE_LOGIN:
		પાછા (syslogin_perform_login(li));
	સ્થિતિ LTYPE_LOGOUT:
		પાછા (syslogin_perform_logout(li));
	મૂળભૂત:
		logit_f("Invalid type field");
		પાછા (0);
	}
}
#endif /* USE_LOGIN */

/* end of file log-syslogin.c */

/**
 ** Low-level lastlog functions
 **/

#ifdef USE_LASTLOG

#જો !defined(LASTLOG_WRITE_PUTUTXLINE) || !defined(HAVE_GETLASTLOGXBYNAME)
/* open the file (using filemode) and seek to the login entry */
સ્થિર પૂર્ણાંક
lastlog_openseek(સંરચના logininfo *li, પૂર્ણાંક *fd, પૂર્ણાંક filemode)
{
	off_t offset;
	અક્ષર lastlog_file[1024];
	સંરચના stat st;

	જો (stat(LASTLOG_FILE, &st) != 0) {
		logit("%s: Couldn't stat %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		પાછા (0);
	}
	જો (S_ISDIR(st.st_mode)) {
		snprintf(lastlog_file, કદ(lastlog_file), "%s/%s",
		    LASTLOG_FILE, li->username);
	} નહીંતર જો (S_ISREG(st.st_mode)) {
		strlcpy(lastlog_file, LASTLOG_FILE, કદ(lastlog_file));
	} નહીંતર {
		logit("%s: %.100s is not a file or directory!", __func__,
		    LASTLOG_FILE);
		પાછા (0);
	}

	*fd = open(lastlog_file, filemode, 0600);
	જો (*fd < 0) {
		debug("%s: Couldn't open %s: %s", __func__,
		    lastlog_file, strerror(errno));
		પાછા (0);
	}

	જો (S_ISREG(st.st_mode)) {
		/* find this uid's offset in the lastlog file */
		offset = (off_t) ((u_long)li->uid * કદ(સંરચના lastlog));

		જો (lseek(*fd, offset, SEEK_SET) != offset) {
			logit("%s: %s->lseek(): %s", __func__,
			    lastlog_file, strerror(errno));
			close(*fd);
			પાછા (0);
		}
	}

	પાછા (1);
}
#endif /* !LASTLOG_WRITE_PUTUTXLINE || !HAVE_GETLASTLOGXBYNAME */

#ifdef LASTLOG_WRITE_PUTUTXLINE
પૂર્ણાંક
lastlog_write_entry(સંરચના logininfo *li)
{
	પસંદગી(li->type) {
	સ્થિતિ LTYPE_LOGIN:
		પાછા 1; /* lastlog written by pututxline */
	મૂળભૂત:
		logit("lastlog_write_entry: Invalid type field");
		પાછા 0;
	}
}
#નહીંતર /* LASTLOG_WRITE_PUTUTXLINE */
પૂર્ણાંક
lastlog_write_entry(સંરચના logininfo *li)
{
	સંરચના lastlog last;
	પૂર્ણાંક fd;

	પસંદગી(li->type) {
	સ્થિતિ LTYPE_LOGIN:
		/* create our struct lastlog */
		memset(&last, '\0', કદ(last));
		લીટી_stripname(last.ll_લીટી, li->લીટી, કદ(last.ll_લીટી));
		strlcpy(last.ll_host, li->hostname,
		    MIN_SIZEOF(last.ll_host, li->hostname));
		last.ll_time = li->tv_sec;

		જો (!lastlog_openseek(li, &fd, O_RDWR|O_CREAT))
			પાછા (0);

		/* write the entry */
		જો (atomicio(vwrite, fd, &last, કદ(last)) != કદ(last)) {
			close(fd);
			logit("%s: Error writing to %s: %s", __func__,
			    LASTLOG_FILE, strerror(errno));
			પાછા (0);
		}

		close(fd);
		પાછા (1);
	મૂળભૂત:
		logit_f("Invalid type field");
		પાછા (0);
	}
}
#endif /* LASTLOG_WRITE_PUTUTXLINE */

#ifdef HAVE_GETLASTLOGXBYNAME
પૂર્ણાંક
lastlog_get_entry(સંરચના logininfo *li)
{
	સંરચના lastlogx l, *ll;

	જો ((ll = getlastlogxbyname(li->username, &l)) == ખાલી) {
		memset(&l, '\0', કદ(l));
		ll = &l;
	}
	લીટી_fullname(li->લીટી, ll->ll_લીટી, કદ(li->લીટી));
	strlcpy(li->hostname, ll->ll_host,
		MIN_SIZEOF(li->hostname, ll->ll_host));
	li->tv_sec = ll->ll_tv.tv_sec;
	li->tv_usec = ll->ll_tv.tv_usec;
	પાછા (1);
}
#નહીંતર /* HAVE_GETLASTLOGXBYNAME */
પૂર્ણાંક
lastlog_get_entry(સંરચના logininfo *li)
{
	સંરચના lastlog last;
	પૂર્ણાંક fd, ret;

	જો (!lastlog_openseek(li, &fd, O_RDONLY))
		પાછા (0);

	ret = atomicio(પઠ, fd, &last, કદ(last));
	close(fd);

	પસંદગી (ret) {
	સ્થિતિ 0:
		memset(&last, '\0', કદ(last));
		/* FALLTHRU */
	સ્થિતિ કદ(last):
		લીટી_fullname(li->લીટી, last.ll_લીટી, કદ(li->લીટી));
		strlcpy(li->hostname, last.ll_host,
		    MIN_SIZEOF(li->hostname, last.ll_host));
		li->tv_sec = last.ll_time;
		પાછા (1);
	સ્થિતિ -1:
		error("%s: Error reading from %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		પાછા (0);
	મૂળભૂત:
		error("%s: Error reading from %s: Expecting %d, got %d",
		    __func__, LASTLOG_FILE, (પૂર્ણાંક)કદ(last), ret);
		પાછા (0);
	}

	/* NOTREACHED */
	પાછા (0);
}
#endif /* HAVE_GETLASTLOGXBYNAME */
#endif /* USE_LASTLOG */

#જો defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
પૂર્ણાંક
utmpx_get_entry(સંરચના logininfo *li)
{
	સંરચના utmpx *utx;

	જો (setutxdb(UTXDB_LASTLOGIN, ખાલી) != 0)
		પાછા (0);
	utx = getutxuser(li->username);
	જો (utx == ખાલી) {
		endutxent();
		પાછા (0);
	}

	લીટી_fullname(li->લીટી, utx->ut_લીટી,
	    MIN_SIZEOF(li->લીટી, utx->ut_લીટી));
	strlcpy(li->hostname, utx->ut_host,
	    MIN_SIZEOF(li->hostname, utx->ut_host));
	li->tv_sec = utx->ut_tv.tv_sec;
	li->tv_usec = utx->ut_tv.tv_usec;
	endutxent();
	પાછા (1);
}
#endif /* USE_UTMPX && HAVE_SETUTXDB && UTXDB_LASTLOGIN && HAVE_GETUTXUSER */

#ifdef USE_BTMP
/*
 * Logs failed login attempts in _PATH_BTMP if that exists.
 * The most common login failure is to give password instead of username.
 * So the _PATH_BTMP file is checked for the correct permission, so that only
 * root can read it.
 */
શૂન્ય
record_failed_login(સંરચના ssh *ssh, અચલ અક્ષર *username, અચલ અક્ષર *hostname,
    અચલ અક્ષર *ttyn)
{
	પૂર્ણાંક fd;
	સંરચના utmp ut;
	સંરચના logininfo li;
	socklen_t fromlen = કદ(li.hostaddr);
	time_t t;
	સંરચના stat fst;

	જો (geteuid() != 0)
		પાછા;
	જો ((fd = open(_PATH_BTMP, O_WRONLY | O_APPEND)) < 0) {
		debug("Unable to open the btmp file %s: %s", _PATH_BTMP,
		    strerror(errno));
		પાછા;
	}
	જો (fstat(fd, &fst) < 0) {
		logit("%s: fstat of %s failed: %s", __func__, _PATH_BTMP,
		    strerror(errno));
		જાઓ out;
	}
	જો ((fst.st_mode & (S_IXGRP | S_IRWXO)) || fst.st_uid != 0) {
		logit("Excess permission or bad ownership on file %s",
		    _PATH_BTMP);
		જાઓ out;
	}

	/* Construct a logininfo and turn it into a utmp */
	memset(&li, 0, કદ(li));
	li.type = LTYPE_FAILED;
	li.pid = getpid();
	strlcpy(li.લીટી, "ssh:notty", કદ(li.લીટી));
	strlcpy(li.username, username, કદ(li.username));
	strlcpy(li.hostname, hostname, કદ(li.hostname));
	time(&t);
	li.tv_sec = t > 0 ? (unsigned long)t : 0;
	જો (ssh_packet_connection_is_on_socket(ssh)) {
		(શૂન્ય)getpeername(ssh_packet_get_connection_in(ssh),
		    &li.hostaddr.sa, &fromlen);
	}
	construct_utmp(&li, &ut);

	જો (atomicio(vwrite, fd, &ut, કદ(ut)) != કદ(ut)) {
		error("Failed to write to %s: %s", _PATH_BTMP,
		    strerror(errno));
	}
out:
	close(fd);
}
#endif	/* USE_BTMP */
