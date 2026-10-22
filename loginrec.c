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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/time.h>

#അന്തര്ഭാവ <netinet/in.h>

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "loginrec.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "misc.h"

# include <util.h>

#ifdef USE_WTMPDB
# include <wtmpdb.h>
#endif

/**
 ** prototypes for helper functions in this file
 **/

#എങ്കിൽ HAVE_UTMP_H
ശൂന്യം set_utmp_time(ഘടന logininfo *li, ഘടന utmp *ut);
ശൂന്യം construct_utmp(ഘടന logininfo *li, ഘടന utmp *ut);
#endif

#ifdef HAVE_UTMPX_H
ശൂന്യം set_utmpx_time(ഘടന logininfo *li, ഘടന utmpx *ut);
ശൂന്യം construct_utmpx(ഘടന logininfo *li, ഘടന utmpx *ut);
#endif

പൂർണ്ണസംഖ്യ utmp_write_entry(ഘടന logininfo *li);
പൂർണ്ണസംഖ്യ utmpx_write_entry(ഘടന logininfo *li);
പൂർണ്ണസംഖ്യ wtmp_write_entry(ഘടന logininfo *li);
പൂർണ്ണസംഖ്യ wtmpx_write_entry(ഘടന logininfo *li);
പൂർണ്ണസംഖ്യ lastlog_write_entry(ഘടന logininfo *li);
പൂർണ്ണസംഖ്യ syslogin_write_entry(ഘടന logininfo *li);
#ifdef USE_WTMPDB
പൂർണ്ണസംഖ്യ wtmpdb_write_entry(ഘടന logininfo *li);
#endif

പൂർണ്ണസംഖ്യ getlast_entry(ഘടന logininfo *li);
പൂർണ്ണസംഖ്യ lastlog_get_entry(ഘടന logininfo *li);
പൂർണ്ണസംഖ്യ utmpx_get_entry(ഘടന logininfo *li);
പൂർണ്ണസംഖ്യ wtmp_get_entry(ഘടന logininfo *li);
പൂർണ്ണസംഖ്യ wtmpx_get_entry(ഘടന logininfo *li);

ബാഹ്യ ഘടന sshbuf *loginmsg;

/* pick the shortest string */
#define MIN_SIZEOF(s1,s2) (വലുപ്പം(s1) < വലുപ്പം(s2) ? വലുപ്പം(s1) : വലുപ്പം(s2))

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
പൂർണ്ണസംഖ്യ
login_login(ഘടന logininfo *li)
{
	li->type = LTYPE_LOGIN;
	തിരികെ (login_write(li));
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
പൂർണ്ണസംഖ്യ
login_logout(ഘടന logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	തിരികെ (login_write(li));
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
unsigned പൂർണ്ണസംഖ്യ
login_get_lastlog_time(സ്ഥിരം uid_t uid)
{
	ഘടന logininfo li;

	എങ്കിൽ (login_get_lastlog(&li, uid))
		തിരികെ (li.tv_sec);
	അല്ലെങ്കിൽ
		തിരികെ (0);
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
ഘടന logininfo *
login_get_lastlog(ഘടന logininfo *li, സ്ഥിരം uid_t uid)
{
	ഘടന passwd *pw;

	memset(li, '\0', വലുപ്പം(*li));
	li->uid = uid;

	/*
	 * If we don't have a 'real' lastlog, we need the username to
	 * reliably search wtmp(x) for the last login (see
	 * wtmp_get_entry().)
	 */
	pw = getpwuid(uid);
	എങ്കിൽ (pw == ശൂന്യ)
		fatal("%s: Cannot find account for uid %ld", __func__,
		    (long)uid);

	എങ്കിൽ (strlcpy(li->username, pw->pw_name, വലുപ്പം(li->username)) >=
	    വലുപ്പം(li->username)) {
		error("%s: username too long (%lu > max %lu)", __func__,
		    (unsigned long)strlen(pw->pw_name),
		    (unsigned long)വലുപ്പം(li->username) - 1);
		തിരികെ ശൂന്യ;
	}

	എങ്കിൽ (getlast_entry(li))
		തിരികെ (li);
	അല്ലെങ്കിൽ
		തിരികെ (ശൂന്യ);
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
ഘടന
logininfo *login_alloc_entry(pid_t pid, സ്ഥിരം അക്ഷരം *username,
    സ്ഥിരം അക്ഷരം *hostname, സ്ഥിരം അക്ഷരം *വരി)
{
	ഘടന logininfo *newli;

	newli = xmalloc(വലുപ്പം(*newli));
	login_init_entry(newli, pid, username, hostname, വരി);
	തിരികെ (newli);
}


/* login_free_entry(struct logininfo *)    - free struct memory */
ശൂന്യം
login_free_entry(ഘടന logininfo *li)
{
	സ്വതന്ത്രം(li);
}


/* login_init_entry(struct logininfo *, int, char*, char*, char*)
 *                                        - initialise a struct logininfo
 *
 * Populates a new struct logininfo, a data structure meant to carry
 * the information required to portably record login info.
 *
 * Returns: 1
 */
പൂർണ്ണസംഖ്യ
login_init_entry(ഘടന logininfo *li, pid_t pid, സ്ഥിരം അക്ഷരം *username,
    സ്ഥിരം അക്ഷരം *hostname, സ്ഥിരം അക്ഷരം *വരി)
{
	ഘടന passwd *pw;

	memset(li, 0, വലുപ്പം(*li));

	li->pid = pid;

	/* set the line information */
	എങ്കിൽ (വരി)
		വരി_fullname(li->വരി, വരി, വലുപ്പം(li->വരി));

	എങ്കിൽ (username) {
		strlcpy(li->username, username, വലുപ്പം(li->username));
		pw = getpwnam(li->username);
		എങ്കിൽ (pw == ശൂന്യ) {
			fatal("%s: Cannot find user \"%s\"", __func__,
			    li->username);
		}
		li->uid = pw->pw_uid;
	}

	എങ്കിൽ (hostname)
		strlcpy(li->hostname, hostname, വലുപ്പം(li->hostname));

	തിരികെ (1);
}

/*
 * login_set_current_time(struct logininfo *)    - set the current time
 *
 * Set the current time in a logininfo structure. This function is
 * meant to eliminate the need to deal with system dependencies for
 * time handling.
 */
ശൂന്യം
login_set_current_time(ഘടന logininfo *li)
{
	ഘടന timeval tv;

	gettimeofday(&tv, ശൂന്യ);

	li->tv_sec = tv.tv_sec;
	li->tv_usec = tv.tv_usec;
}

/* copy a sockaddr_* into our logininfo */
ശൂന്യം
login_set_addr(ഘടന logininfo *li, സ്ഥിരം ഘടന sockaddr *sa,
    സ്ഥിരം unsigned പൂർണ്ണസംഖ്യ sa_size)
{
	unsigned പൂർണ്ണസംഖ്യ bufsize = sa_size;

	/* make sure we don't overrun our union */
	എങ്കിൽ (വലുപ്പം(li->hostaddr) < sa_size)
		bufsize = വലുപ്പം(li->hostaddr);

	memcpy(&li->hostaddr.sa, sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/
പൂർണ്ണസംഖ്യ
login_write(ഘടന logininfo *li)
{
#ifndef HAVE_CYGWIN
	എങ്കിൽ (geteuid() != 0) {
		logit("Attempt to write login records by non-root user (aborting)");
		തിരികെ (1);
	}
#endif

	/* set the timestamp */
	login_set_current_time(li);
#ifdef USE_LOGIN
	syslogin_write_entry(li);
#endif
#ifdef USE_LASTLOG
	എങ്കിൽ (li->type == LTYPE_LOGIN)
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
	എങ്കിൽ (li->type == LTYPE_LOGIN &&
	    !sys_auth_record_login(li->username,li->hostname,li->വരി,
	    loginmsg))
		logit("Writing login record failed for %s", li->username);
#endif
#ifdef SSH_AUDIT_EVENTS
	എങ്കിൽ (li->type == LTYPE_LOGIN)
		audit_session_open(li);
	അല്ലെങ്കിൽ എങ്കിൽ (li->type == LTYPE_LOGOUT)
		audit_session_close(li);
#endif
	തിരികെ (0);
}

#ifdef LOGIN_NEEDS_UTMPX
പൂർണ്ണസംഖ്യ
login_utmp_only(ഘടന logininfo *li)
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
	തിരികെ (0);
}
#endif

/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
പൂർണ്ണസംഖ്യ
getlast_entry(ഘടന logininfo *li)
{
#ifdef USE_LASTLOG
	തിരികെ(lastlog_get_entry(li));
#അല്ലെങ്കിൽ /* !USE_LASTLOG */
#എങ്കിൽ defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
	തിരികെ (utmpx_get_entry(li));
#endif

#എങ്കിൽ defined(DISABLE_LASTLOG)
	/* On some systems we shouldn't even try to obtain last login
	 * time, e.g. AIX */
	തിരികെ (0);
# elif defined(USE_WTMP) && \
    (defined(HAVE_TIME_IN_UTMP) || defined(HAVE_TV_IN_UTMP))
	/* retrieve last login time from utmp */
	തിരികെ (wtmp_get_entry(li));
# elif defined(USE_WTMPX) && \
    (defined(HAVE_TIME_IN_UTMPX) || defined(HAVE_TV_IN_UTMPX))
	/* If wtmp isn't available, try wtmpx */
	തിരികെ (wtmpx_get_entry(li));
# അല്ലെങ്കിൽ
	/* Give up: No means of retrieving last login time */
	തിരികെ (0);
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
അക്ഷരം *
വരി_fullname(അക്ഷരം *dst, സ്ഥിരം അക്ഷരം *src, u_int dstsize)
{
	memset(dst, '\0', dstsize);
	എങ്കിൽ ((strncmp(src, "/dev/", 5) == 0) || (dstsize < (strlen(src) + 5)))
		strlcpy(dst, src, dstsize);
	അല്ലെങ്കിൽ {
		strlcpy(dst, "/dev/", dstsize);
		strlcat(dst, src, dstsize);
	}
	തിരികെ (dst);
}

/* line_stripname(): strip the leading '/dev' if it exists, return dst */
അക്ഷരം *
വരി_stripname(അക്ഷരം *dst, സ്ഥിരം അക്ഷരം *src, പൂർണ്ണസംഖ്യ dstsize)
{
	memset(dst, '\0', dstsize);
	എങ്കിൽ (strncmp(src, "/dev/", 5) == 0)
		strlcpy(dst, src + 5, dstsize);
	അല്ലെങ്കിൽ
		strlcpy(dst, src, dstsize);
	തിരികെ (dst);
}

/*
 * line_abbrevname(): Return the abbreviated (usually four-character)
 * form of the line (Just use the last <dstsize> characters of the
 * full name.)
 *
 * NOTE: use strncpy because we do NOT necessarily want zero
 * termination
 */
അക്ഷരം *
വരി_abbrevname(അക്ഷരം *dst, സ്ഥിരം അക്ഷരം *src, പൂർണ്ണസംഖ്യ dstsize)
{
	size_t len;

	memset(dst, '\0', dstsize);

	എങ്കിൽ (strcmp(src, "ssh:notty") == 0)
		തിരികെ dst;

	/* Always skip prefix if present */
	എങ്കിൽ (strncmp(src, "/dev/", 5) == 0)
		src += 5;

#ifdef WITH_ABBREV_NO_TTY
	എങ്കിൽ (strncmp(src, "tty", 3) == 0)
		src += 3;
#endif

	len = strlen(src);

	എങ്കിൽ (len > 0) {
		എങ്കിൽ (((പൂർണ്ണസംഖ്യ)len - dstsize) > 0)
			src +=  ((പൂർണ്ണസംഖ്യ)len - dstsize);

		/* note: _don't_ change this to strlcpy */
		strncpy(dst, src, (size_t)dstsize);
	}

	തിരികെ (dst);
}

/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#എങ്കിൽ defined(USE_BTMP) || defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
ശൂന്യം
set_utmp_time(ഘടന logininfo *li, ഘടന utmp *ut)
{
# എങ്കിൽ defined(HAVE_TV_IN_UTMP)
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMP)
	ut->ut_time = li->tv_sec;
# endif
}

ശൂന്യം
construct_utmp(ഘടന logininfo *li,
		    ഘടന utmp *ut)
{
# ifdef HAVE_ADDR_V6_IN_UTMP
	ഘടന sockaddr_in6 *sa6;
# endif

	memset(ut, '\0', വലുപ്പം(*ut));

	/* First fill out fields used for both logins and logouts */

# ifdef HAVE_ID_IN_UTMP
	വരി_abbrevname(ut->ut_id, li->വരി, വലുപ്പം(ut->ut_id));
# endif

# ifdef HAVE_TYPE_IN_UTMP
	/* This is done here to keep utmp constants out of struct logininfo */
	തിരഞ്ഞെടുപ്പ് (li->type) {
	അവസ്ഥ LTYPE_FAILED:
		ut->ut_type = LOGIN_PROCESS;
		നിർത്തുക;
	അവസ്ഥ LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		നിർത്തുക;
	അവസ്ഥ LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		നിർത്തുക;
	}
# endif
	set_utmp_time(li, ut);

	വരി_stripname(ut->ut_വരി, li->വരി, വലുപ്പം(ut->ut_വരി));

# ifdef HAVE_PID_IN_UTMP
	ut->ut_pid = li->pid;
# endif

	/* If we're logging out, leave all other fields blank */
	എങ്കിൽ (li->type == LTYPE_LOGOUT)
		തിരികെ;

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
	എങ്കിൽ (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMP
	/* this is just a 128-bit IPv6 address */
	എങ്കിൽ (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((ഘടന sockaddr_in6 *)&li->hostaddr.sa);
		memcpy(ut->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		എങ്കിൽ (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
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

#എങ്കിൽ defined(USE_UTMPX) || defined (USE_WTMPX)
/* build the utmpx structure */
ശൂന്യം
set_utmpx_time(ഘടന logininfo *li, ഘടന utmpx *utx)
{
# എങ്കിൽ defined(HAVE_TV_IN_UTMPX)
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMPX)
	utx->ut_time = li->tv_sec;
# endif
}

ശൂന്യം
construct_utmpx(ഘടന logininfo *li, ഘടന utmpx *utx)
{
# ifdef HAVE_ADDR_V6_IN_UTMPX
	ഘടന sockaddr_in6 *sa6;
#  endif
	memset(utx, '\0', വലുപ്പം(*utx));

# ifdef HAVE_ID_IN_UTMPX
	വരി_abbrevname(utx->ut_id, li->വരി, വലുപ്പം(utx->ut_id));
# endif

	/* this is done here to keep utmp constants out of loginrec.h */
	തിരഞ്ഞെടുപ്പ് (li->type) {
	അവസ്ഥ LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		നിർത്തുക;
	അവസ്ഥ LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		നിർത്തുക;
	}
	വരി_stripname(utx->ut_വരി, li->വരി, വലുപ്പം(utx->ut_വരി));
	set_utmpx_time(li, utx);
	utx->ut_pid = li->pid;

	/* strncpy(): Don't necessarily want null termination */
	strncpy(utx->ut_user, li->username,
	    MIN_SIZEOF(utx->ut_user, li->username));

	എങ്കിൽ (li->type == LTYPE_LOGOUT)
		തിരികെ;

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
	എങ്കിൽ (li->hostaddr.sa.sa_family == AF_INET)
		utx->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMPX
	/* this is just a 128-bit IPv6 address */
	എങ്കിൽ (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((ഘടന sockaddr_in6 *)&li->hostaddr.sa);
		memcpy(utx->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		എങ്കിൽ (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			utx->ut_addr_v6[0] = utx->ut_addr_v6[3];
			utx->ut_addr_v6[1] = 0;
			utx->ut_addr_v6[2] = 0;
			utx->ut_addr_v6[3] = 0;
		}
	}
# endif
# ifdef HAVE_SYSLEN_IN_UTMPX
	/* ut_syslen is the length of the utx_host string */
	utx->ut_syslen = MINIMUM(strlen(li->hostname), വലുപ്പം(utx->ut_host));
# endif
}
#endif /* USE_UTMPX || USE_WTMPX */

/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */
#ifdef USE_UTMP

/* if we can, use pututline() etc. */
# എങ്കിൽ !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
	defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
# endif


/* write a utmp entry with the system's help (pututline() and pals) */
# ifdef UTMP_USE_LIBRARY
സ്ഥിതം പൂർണ്ണസംഖ്യ
utmp_write_library(ഘടന logininfo *li, ഘടന utmp *ut)
{
	setutent();
	pututline(ut);
#  ifdef HAVE_ENDUTENT
	endutent();
#  endif
	തിരികെ (1);
}
# അല്ലെങ്കിൽ /* UTMP_USE_LIBRARY */

/*
 * Write a utmp entry direct to the file
 * This is a slightly modification of code in OpenBSD's login.c
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
utmp_write_direct(ഘടന logininfo *li, ഘടന utmp *ut)
{
	ഘടന utmp old_ut;
	രജിസ്റ്റർ പൂർണ്ണസംഖ്യ fd;
	പൂർണ്ണസംഖ്യ tty;

	/* FIXME: (ATL) ttyslot() needs local implementation */

#എങ്കിൽ defined(HAVE_GETTTYENT)
	ഘടന ttyent *ty;

	tty=0;
	setttyent();
	ആകുമ്പോൾ (ശൂന്യ != (ty = getttyent())) {
		tty++;
		എങ്കിൽ (!strncmp(ty->ty_name, ut->ut_വരി, വലുപ്പം(ut->ut_വരി)))
			നിർത്തുക;
	}
	endttyent();

	എങ്കിൽ (ശൂന്യ == ty) {
		logit_f("tty not found");
		തിരികെ (0);
	}
#അല്ലെങ്കിൽ /* FIXME */

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

#endif /* HAVE_GETTTYENT */

	എങ്കിൽ (tty > 0 && (fd = open(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		off_t pos, ret;

		pos = (off_t)tty * വലുപ്പം(ഘടന utmp);
		എങ്കിൽ ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			തിരികെ (0);
		}
		എങ്കിൽ (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			തിരികെ (0);
		}
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		എങ്കിൽ (atomicio(പഠ, fd, &old_ut, വലുപ്പം(old_ut)) == വലുപ്പം(old_ut) &&
		    (ut->ut_host[0] == '\0') && (old_ut.ut_host[0] != '\0') &&
		    (strncmp(old_ut.ut_വരി, ut->ut_വരി, വലുപ്പം(ut->ut_വരി)) == 0) &&
		    (strncmp(old_ut.ut_name, ut->ut_name, വലുപ്പം(ut->ut_name)) == 0))
			memcpy(ut->ut_host, old_ut.ut_host, വലുപ്പം(ut->ut_host));

		എങ്കിൽ ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			തിരികെ (0);
		}
		എങ്കിൽ (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			തിരികെ (0);
		}
		എങ്കിൽ (atomicio(vwrite, fd, ut, വലുപ്പം(*ut)) != വലുപ്പം(*ut)) {
			logit("%s: error writing %s: %s", __func__,
			    UTMP_FILE, strerror(errno));
			close(fd);
			തിരികെ (0);
		}

		close(fd);
		തിരികെ (1);
	} അല്ലെങ്കിൽ {
		തിരികെ (0);
	}
}
# endif /* UTMP_USE_LIBRARY */

സ്ഥിതം പൂർണ്ണസംഖ്യ
utmp_perform_login(ഘടന logininfo *li)
{
	ഘടന utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	എങ്കിൽ (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		തിരികെ (0);
	}
# അല്ലെങ്കിൽ
	എങ്കിൽ (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		തിരികെ (0);
	}
# endif
	തിരികെ (1);
}


സ്ഥിതം പൂർണ്ണസംഖ്യ
utmp_perform_logout(ഘടന logininfo *li)
{
	ഘടന utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	എങ്കിൽ (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		തിരികെ (0);
	}
# അല്ലെങ്കിൽ
	എങ്കിൽ (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		തിരികെ (0);
	}
# endif
	തിരികെ (1);
}


പൂർണ്ണസംഖ്യ
utmp_write_entry(ഘടന logininfo *li)
{
	തിരഞ്ഞെടുപ്പ്(li->type) {
	അവസ്ഥ LTYPE_LOGIN:
		തിരികെ (utmp_perform_login(li));

	അവസ്ഥ LTYPE_LOGOUT:
		തിരികെ (utmp_perform_logout(li));

	സ്ഥിരസ്ഥിതി:
		logit_f("invalid type field");
		തിരികെ (0);
	}
}
#endif /* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#ifdef USE_UTMPX

/* if we have the wherewithal, use pututxline etc. */
# എങ്കിൽ !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) && \
	defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
# endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
# ifdef UTMPX_USE_LIBRARY
സ്ഥിതം പൂർണ്ണസംഖ്യ
utmpx_write_library(ഘടന logininfo *li, ഘടന utmpx *utx)
{
	setutxent();
	pututxline(utx);

#  ifdef HAVE_ENDUTXENT
	endutxent();
#  endif
	തിരികെ (1);
}

# അല്ലെങ്കിൽ /* UTMPX_USE_LIBRARY */

/* write a utmp entry direct to the file */
സ്ഥിതം പൂർണ്ണസംഖ്യ
utmpx_write_direct(ഘടന logininfo *li, ഘടന utmpx *utx)
{
	logit_f("not implemented!");
	തിരികെ (0);
}
# endif /* UTMPX_USE_LIBRARY */

സ്ഥിതം പൂർണ്ണസംഖ്യ
utmpx_perform_login(ഘടന logininfo *li)
{
	ഘടന utmpx utx;

	construct_utmpx(li, &utx);
# ifdef UTMPX_USE_LIBRARY
	എങ്കിൽ (!utmpx_write_library(li, &utx)) {
		logit_f("utmp_write_library() failed");
		തിരികെ (0);
	}
# അല്ലെങ്കിൽ
	എങ്കിൽ (!utmpx_write_direct(li, &utx)) {
		logit_f("utmp_write_direct() failed");
		തിരികെ (0);
	}
# endif
	തിരികെ (1);
}


സ്ഥിതം പൂർണ്ണസംഖ്യ
utmpx_perform_logout(ഘടന logininfo *li)
{
	ഘടന utmpx utx;

	construct_utmpx(li, &utx);
# ifdef HAVE_ID_IN_UTMPX
	വരി_abbrevname(utx.ut_id, li->വരി, വലുപ്പം(utx.ut_id));
# endif
# ifdef HAVE_TYPE_IN_UTMPX
	utx.ut_type = DEAD_PROCESS;
# endif

# ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
# അല്ലെങ്കിൽ
	utmpx_write_direct(li, &utx);
# endif
	തിരികെ (1);
}

പൂർണ്ണസംഖ്യ
utmpx_write_entry(ഘടന logininfo *li)
{
	തിരഞ്ഞെടുപ്പ്(li->type) {
	അവസ്ഥ LTYPE_LOGIN:
		തിരികെ (utmpx_perform_login(li));
	അവസ്ഥ LTYPE_LOGOUT:
		തിരികെ (utmpx_perform_logout(li));
	സ്ഥിരസ്ഥിതി:
		logit_f("invalid type field");
		തിരികെ (0);
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
സ്ഥിതം പൂർണ്ണസംഖ്യ
wtmp_write(ഘടന logininfo *li, ഘടന utmp *ut)
{
	ഘടന stat buf;
	പൂർണ്ണസംഖ്യ fd, ret = 1;

	എങ്കിൽ ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem writing %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		തിരികെ (0);
	}
	എങ്കിൽ (fstat(fd, &buf) == 0)
		എങ്കിൽ (atomicio(vwrite, fd, ut, വലുപ്പം(*ut)) != വലുപ്പം(*ut)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMP_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);
	തിരികെ (ret);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
wtmp_perform_login(ഘടന logininfo *li)
{
	ഘടന utmp ut;

	construct_utmp(li, &ut);
	തിരികെ (wtmp_write(li, &ut));
}


സ്ഥിതം പൂർണ്ണസംഖ്യ
wtmp_perform_logout(ഘടന logininfo *li)
{
	ഘടന utmp ut;

	construct_utmp(li, &ut);
	തിരികെ (wtmp_write(li, &ut));
}


പൂർണ്ണസംഖ്യ
wtmp_write_entry(ഘടന logininfo *li)
{
	തിരഞ്ഞെടുപ്പ്(li->type) {
	അവസ്ഥ LTYPE_LOGIN:
		തിരികെ (wtmp_perform_login(li));
	അവസ്ഥ LTYPE_LOGOUT:
		തിരികെ (wtmp_perform_logout(li));
	സ്ഥിരസ്ഥിതി:
		logit_f("invalid type field");
		തിരികെ (0);
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
സ്ഥിതം പൂർണ്ണസംഖ്യ
wtmp_islogin(ഘടന logininfo *li, ഘടന utmp *ut)
{
	എങ്കിൽ (strncmp(li->username, ut->ut_name,
	    MIN_SIZEOF(li->username, ut->ut_name)) == 0) {
# ifdef HAVE_TYPE_IN_UTMP
		എങ്കിൽ (ut->ut_type & USER_PROCESS)
			തിരികെ (1);
# അല്ലെങ്കിൽ
		തിരികെ (1);
# endif
	}
	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
wtmp_get_entry(ഘടന logininfo *li)
{
	ഘടന stat st;
	ഘടന utmp ut;
	പൂർണ്ണസംഖ്യ fd, found = 0;

	/* Clear the time entries in our logininfo */
	li->tv_sec = li->tv_usec = 0;

	എങ്കിൽ ((fd = open(WTMP_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		തിരികെ (0);
	}
	എങ്കിൽ (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		close(fd);
		തിരികെ (0);
	}

	/* Seek to the start of the last struct utmp */
	എങ്കിൽ (lseek(fd, -(off_t)വലുപ്പം(ഘടന utmp), SEEK_END) == -1) {
		/* Looks like we've got a fresh wtmp file */
		close(fd);
		തിരികെ (0);
	}

	ആകുമ്പോൾ (!found) {
		എങ്കിൽ (atomicio(പഠ, fd, &ut, വലുപ്പം(ut)) != വലുപ്പം(ut)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMP_FILE, strerror(errno));
			close (fd);
			തിരികെ (0);
		}
		എങ്കിൽ (wtmp_islogin(li, &ut) ) {
			found = 1;
			/*
			 * We've already checked for a time in struct
			 * utmp, in login_getlast()
			 */
# ifdef HAVE_TIME_IN_UTMP
			li->tv_sec = ut.ut_time;
# അല്ലെങ്കിൽ
#  എങ്കിൽ HAVE_TV_IN_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
# endif
			വരി_fullname(li->വരി, ut.ut_വരി,
			    MIN_SIZEOF(li->വരി, ut.ut_വരി));
# ifdef HAVE_HOST_IN_UTMP
			strlcpy(li->hostname, ut.ut_host,
			    MIN_SIZEOF(li->hostname, ut.ut_host));
# endif
			തുടരുക;
		}
		/* Seek back 2 x struct utmp */
		എങ്കിൽ (lseek(fd, -(off_t)(2 * വലുപ്പം(ഘടന utmp)), SEEK_CUR) == -1) {
			/* We've found the start of the file, so quit */
			close(fd);
			തിരികെ (0);
		}
	}

	/* We found an entry. Tidy up and return */
	close(fd);
	തിരികെ (1);
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
സ്ഥിതം പൂർണ്ണസംഖ്യ
wtmpx_write(ഘടന logininfo *li, ഘടന utmpx *utx)
{
#ifndef HAVE_UPDWTMPX
	ഘടന stat buf;
	പൂർണ്ണസംഖ്യ fd, ret = 1;

	എങ്കിൽ ((fd = open(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		തിരികെ (0);
	}

	എങ്കിൽ (fstat(fd, &buf) == 0)
		എങ്കിൽ (atomicio(vwrite, fd, utx, വലുപ്പം(*utx)) != വലുപ്പം(*utx)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);

	തിരികെ (ret);
#അല്ലെങ്കിൽ
	updwtmpx(WTMPX_FILE, utx);
	തിരികെ (1);
#endif
}


സ്ഥിതം പൂർണ്ണസംഖ്യ
wtmpx_perform_login(ഘടന logininfo *li)
{
	ഘടന utmpx utx;

	construct_utmpx(li, &utx);
	തിരികെ (wtmpx_write(li, &utx));
}


സ്ഥിതം പൂർണ്ണസംഖ്യ
wtmpx_perform_logout(ഘടന logininfo *li)
{
	ഘടന utmpx utx;

	construct_utmpx(li, &utx);
	തിരികെ (wtmpx_write(li, &utx));
}


പൂർണ്ണസംഖ്യ
wtmpx_write_entry(ഘടന logininfo *li)
{
	തിരഞ്ഞെടുപ്പ്(li->type) {
	അവസ്ഥ LTYPE_LOGIN:
		തിരികെ (wtmpx_perform_login(li));
	അവസ്ഥ LTYPE_LOGOUT:
		തിരികെ (wtmpx_perform_logout(li));
	സ്ഥിരസ്ഥിതി:
		logit_f("invalid type field");
		തിരികെ (0);
	}
}

/* Please see the notes above wtmp_islogin() for information about the
   next two functions */

/* Return true if this wtmpx entry indicates a login */
സ്ഥിതം പൂർണ്ണസംഖ്യ
wtmpx_islogin(ഘടന logininfo *li, ഘടന utmpx *utx)
{
	എങ്കിൽ (strncmp(li->username, utx->ut_user,
	    MIN_SIZEOF(li->username, utx->ut_user)) == 0 ) {
# ifdef HAVE_TYPE_IN_UTMPX
		എങ്കിൽ (utx->ut_type == USER_PROCESS)
			തിരികെ (1);
# അല്ലെങ്കിൽ
		തിരികെ (1);
# endif
	}
	തിരികെ (0);
}


പൂർണ്ണസംഖ്യ
wtmpx_get_entry(ഘടന logininfo *li)
{
	ഘടന stat st;
	ഘടന utmpx utx;
	പൂർണ്ണസംഖ്യ fd, found=0;

	/* Clear the time entries */
	li->tv_sec = li->tv_usec = 0;

	എങ്കിൽ ((fd = open(WTMPX_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		തിരികെ (0);
	}
	എങ്കിൽ (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		close(fd);
		തിരികെ (0);
	}

	/* Seek to the start of the last struct utmpx */
	എങ്കിൽ (lseek(fd, -(off_t)വലുപ്പം(ഘടന utmpx), SEEK_END) == -1 ) {
		/* probably a newly rotated wtmpx file */
		close(fd);
		തിരികെ (0);
	}

	ആകുമ്പോൾ (!found) {
		എങ്കിൽ (atomicio(പഠ, fd, &utx, വലുപ്പം(utx)) != വലുപ്പം(utx)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			close (fd);
			തിരികെ (0);
		}
		/*
		 * Logouts are recorded as a blank username on a particular
		 * line. So, we just need to find the username in struct utmpx
		 */
		എങ്കിൽ (wtmpx_islogin(li, &utx)) {
			found = 1;
# എങ്കിൽ defined(HAVE_TV_IN_UTMPX)
			li->tv_sec = utx.ut_tv.tv_sec;
# elif defined(HAVE_TIME_IN_UTMPX)
			li->tv_sec = utx.ut_time;
# endif
			വരി_fullname(li->വരി, utx.ut_വരി, വലുപ്പം(li->വരി));
# എങ്കിൽ defined(HAVE_HOST_IN_UTMPX)
			strlcpy(li->hostname, utx.ut_host,
			    MIN_SIZEOF(li->hostname, utx.ut_host));
# endif
			തുടരുക;
		}
		എങ്കിൽ (lseek(fd, -(off_t)(2 * വലുപ്പം(ഘടന utmpx)), SEEK_CUR) == -1) {
			close(fd);
			തിരികെ (0);
		}
	}

	close(fd);
	തിരികെ (1);
}
#endif /* USE_WTMPX */

#ifdef USE_WTMPDB
സ്ഥിതം പൂർണ്ണസംഖ്യ
wtmpdb_perform_login(ഘടന logininfo *li)
{
	uint64_t login_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	    li->tv_usec;
	സ്ഥിരം അക്ഷരം *tty;

	എങ്കിൽ (strncmp(li->വരി, "/dev/", 5) == 0)
		tty = &(li->വരി[5]);
	അല്ലെങ്കിൽ
		tty = li->വരി;

	li->wtmpdb_id = wtmpdb_login(ശൂന്യ, USER_PROCESS, li->username,
	    login_time, tty, li->hostname, 0, 0);

	എങ്കിൽ (li->wtmpdb_id < 0)
		തിരികെ (0);

	തിരികെ (1);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
wtmpdb_perform_logout(ഘടന logininfo *li)
{
	uint64_t logout_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	   li->tv_usec;

	എങ്കിൽ (li->wtmpdb_id == 0) {
		സ്ഥിരം അക്ഷരം *tty;

		എങ്കിൽ (strncmp(li->വരി, "/dev/", 5) == 0)
			tty = &(li->വരി[5]);
		അല്ലെങ്കിൽ
			tty = li->വരി;

		li->wtmpdb_id = wtmpdb_get_id(ശൂന്യ, tty, ശൂന്യ);
	}
	wtmpdb_logout(ശൂന്യ, li->wtmpdb_id, logout_time, ശൂന്യ);

	തിരികെ (1);
}

പൂർണ്ണസംഖ്യ
wtmpdb_write_entry(ഘടന logininfo *li)
{
	തിരഞ്ഞെടുപ്പ്(li->type) {
	അവസ്ഥ LTYPE_LOGIN:
		തിരികെ (wtmpdb_perform_login(li));
	അവസ്ഥ LTYPE_LOGOUT:
		തിരികെ (wtmpdb_perform_logout(li));
	സ്ഥിരസ്ഥിതി:
		logit_f("invalid type field");
		തിരികെ (0);
	}
}
#endif

/**
 ** Low-level libutil login() functions
 **/

#ifdef USE_LOGIN
സ്ഥിതം പൂർണ്ണസംഖ്യ
syslogin_perform_login(ഘടന logininfo *li)
{
	ഘടന utmp *ut;

	ut = xmalloc(വലുപ്പം(*ut));
	construct_utmp(li, ut);
	login(ut);
	സ്വതന്ത്രം(ut);

	തിരികെ (1);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
syslogin_perform_logout(ഘടന logininfo *li)
{
# ifdef HAVE_LOGOUT
	അക്ഷരം വരി[UT_LINESIZE];

	(ശൂന്യം)വരി_stripname(വരി, li->വരി, വലുപ്പം(വരി));

	എങ്കിൽ (!logout(വരി))
		logit_f("logout() returned an error");
#  ifdef HAVE_LOGWTMP
	അല്ലെങ്കിൽ
		logwtmp(വരി, "", "");
#  endif
	/* FIXME: (ATL - if the need arises) What to do if we have
	 * login, but no logout?  what if logout but no logwtmp? All
	 * routines are in libutil so they should all be there,
	 * but... */
# endif
	തിരികെ (1);
}

പൂർണ്ണസംഖ്യ
syslogin_write_entry(ഘടന logininfo *li)
{
	തിരഞ്ഞെടുപ്പ് (li->type) {
	അവസ്ഥ LTYPE_LOGIN:
		തിരികെ (syslogin_perform_login(li));
	അവസ്ഥ LTYPE_LOGOUT:
		തിരികെ (syslogin_perform_logout(li));
	സ്ഥിരസ്ഥിതി:
		logit_f("Invalid type field");
		തിരികെ (0);
	}
}
#endif /* USE_LOGIN */

/* end of file log-syslogin.c */

/**
 ** Low-level lastlog functions
 **/

#ifdef USE_LASTLOG

#എങ്കിൽ !defined(LASTLOG_WRITE_PUTUTXLINE) || !defined(HAVE_GETLASTLOGXBYNAME)
/* open the file (using filemode) and seek to the login entry */
സ്ഥിതം പൂർണ്ണസംഖ്യ
lastlog_openseek(ഘടന logininfo *li, പൂർണ്ണസംഖ്യ *fd, പൂർണ്ണസംഖ്യ filemode)
{
	off_t offset;
	അക്ഷരം lastlog_file[1024];
	ഘടന stat st;

	എങ്കിൽ (stat(LASTLOG_FILE, &st) != 0) {
		logit("%s: Couldn't stat %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		തിരികെ (0);
	}
	എങ്കിൽ (S_ISDIR(st.st_mode)) {
		snprintf(lastlog_file, വലുപ്പം(lastlog_file), "%s/%s",
		    LASTLOG_FILE, li->username);
	} അല്ലെങ്കിൽ എങ്കിൽ (S_ISREG(st.st_mode)) {
		strlcpy(lastlog_file, LASTLOG_FILE, വലുപ്പം(lastlog_file));
	} അല്ലെങ്കിൽ {
		logit("%s: %.100s is not a file or directory!", __func__,
		    LASTLOG_FILE);
		തിരികെ (0);
	}

	*fd = open(lastlog_file, filemode, 0600);
	എങ്കിൽ (*fd < 0) {
		debug("%s: Couldn't open %s: %s", __func__,
		    lastlog_file, strerror(errno));
		തിരികെ (0);
	}

	എങ്കിൽ (S_ISREG(st.st_mode)) {
		/* find this uid's offset in the lastlog file */
		offset = (off_t) ((u_long)li->uid * വലുപ്പം(ഘടന lastlog));

		എങ്കിൽ (lseek(*fd, offset, SEEK_SET) != offset) {
			logit("%s: %s->lseek(): %s", __func__,
			    lastlog_file, strerror(errno));
			close(*fd);
			തിരികെ (0);
		}
	}

	തിരികെ (1);
}
#endif /* !LASTLOG_WRITE_PUTUTXLINE || !HAVE_GETLASTLOGXBYNAME */

#ifdef LASTLOG_WRITE_PUTUTXLINE
പൂർണ്ണസംഖ്യ
lastlog_write_entry(ഘടന logininfo *li)
{
	തിരഞ്ഞെടുപ്പ്(li->type) {
	അവസ്ഥ LTYPE_LOGIN:
		തിരികെ 1; /* lastlog written by pututxline */
	സ്ഥിരസ്ഥിതി:
		logit("lastlog_write_entry: Invalid type field");
		തിരികെ 0;
	}
}
#അല്ലെങ്കിൽ /* LASTLOG_WRITE_PUTUTXLINE */
പൂർണ്ണസംഖ്യ
lastlog_write_entry(ഘടന logininfo *li)
{
	ഘടന lastlog last;
	പൂർണ്ണസംഖ്യ fd;

	തിരഞ്ഞെടുപ്പ്(li->type) {
	അവസ്ഥ LTYPE_LOGIN:
		/* create our struct lastlog */
		memset(&last, '\0', വലുപ്പം(last));
		വരി_stripname(last.ll_വരി, li->വരി, വലുപ്പം(last.ll_വരി));
		strlcpy(last.ll_host, li->hostname,
		    MIN_SIZEOF(last.ll_host, li->hostname));
		last.ll_time = li->tv_sec;

		എങ്കിൽ (!lastlog_openseek(li, &fd, O_RDWR|O_CREAT))
			തിരികെ (0);

		/* write the entry */
		എങ്കിൽ (atomicio(vwrite, fd, &last, വലുപ്പം(last)) != വലുപ്പം(last)) {
			close(fd);
			logit("%s: Error writing to %s: %s", __func__,
			    LASTLOG_FILE, strerror(errno));
			തിരികെ (0);
		}

		close(fd);
		തിരികെ (1);
	സ്ഥിരസ്ഥിതി:
		logit_f("Invalid type field");
		തിരികെ (0);
	}
}
#endif /* LASTLOG_WRITE_PUTUTXLINE */

#ifdef HAVE_GETLASTLOGXBYNAME
പൂർണ്ണസംഖ്യ
lastlog_get_entry(ഘടന logininfo *li)
{
	ഘടന lastlogx l, *ll;

	എങ്കിൽ ((ll = getlastlogxbyname(li->username, &l)) == ശൂന്യ) {
		memset(&l, '\0', വലുപ്പം(l));
		ll = &l;
	}
	വരി_fullname(li->വരി, ll->ll_വരി, വലുപ്പം(li->വരി));
	strlcpy(li->hostname, ll->ll_host,
		MIN_SIZEOF(li->hostname, ll->ll_host));
	li->tv_sec = ll->ll_tv.tv_sec;
	li->tv_usec = ll->ll_tv.tv_usec;
	തിരികെ (1);
}
#അല്ലെങ്കിൽ /* HAVE_GETLASTLOGXBYNAME */
പൂർണ്ണസംഖ്യ
lastlog_get_entry(ഘടന logininfo *li)
{
	ഘടന lastlog last;
	പൂർണ്ണസംഖ്യ fd, ret;

	എങ്കിൽ (!lastlog_openseek(li, &fd, O_RDONLY))
		തിരികെ (0);

	ret = atomicio(പഠ, fd, &last, വലുപ്പം(last));
	close(fd);

	തിരഞ്ഞെടുപ്പ് (ret) {
	അവസ്ഥ 0:
		memset(&last, '\0', വലുപ്പം(last));
		/* FALLTHRU */
	അവസ്ഥ വലുപ്പം(last):
		വരി_fullname(li->വരി, last.ll_വരി, വലുപ്പം(li->വരി));
		strlcpy(li->hostname, last.ll_host,
		    MIN_SIZEOF(li->hostname, last.ll_host));
		li->tv_sec = last.ll_time;
		തിരികെ (1);
	അവസ്ഥ -1:
		error("%s: Error reading from %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		തിരികെ (0);
	സ്ഥിരസ്ഥിതി:
		error("%s: Error reading from %s: Expecting %d, got %d",
		    __func__, LASTLOG_FILE, (പൂർണ്ണസംഖ്യ)വലുപ്പം(last), ret);
		തിരികെ (0);
	}

	/* NOTREACHED */
	തിരികെ (0);
}
#endif /* HAVE_GETLASTLOGXBYNAME */
#endif /* USE_LASTLOG */

#എങ്കിൽ defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
പൂർണ്ണസംഖ്യ
utmpx_get_entry(ഘടന logininfo *li)
{
	ഘടന utmpx *utx;

	എങ്കിൽ (setutxdb(UTXDB_LASTLOGIN, ശൂന്യ) != 0)
		തിരികെ (0);
	utx = getutxuser(li->username);
	എങ്കിൽ (utx == ശൂന്യ) {
		endutxent();
		തിരികെ (0);
	}

	വരി_fullname(li->വരി, utx->ut_വരി,
	    MIN_SIZEOF(li->വരി, utx->ut_വരി));
	strlcpy(li->hostname, utx->ut_host,
	    MIN_SIZEOF(li->hostname, utx->ut_host));
	li->tv_sec = utx->ut_tv.tv_sec;
	li->tv_usec = utx->ut_tv.tv_usec;
	endutxent();
	തിരികെ (1);
}
#endif /* USE_UTMPX && HAVE_SETUTXDB && UTXDB_LASTLOGIN && HAVE_GETUTXUSER */

#ifdef USE_BTMP
/*
 * Logs failed login attempts in _PATH_BTMP if that exists.
 * The most common login failure is to give password instead of username.
 * So the _PATH_BTMP file is checked for the correct permission, so that only
 * root can read it.
 */
ശൂന്യം
record_failed_login(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *username, സ്ഥിരം അക്ഷരം *hostname,
    സ്ഥിരം അക്ഷരം *ttyn)
{
	പൂർണ്ണസംഖ്യ fd;
	ഘടന utmp ut;
	ഘടന logininfo li;
	socklen_t fromlen = വലുപ്പം(li.hostaddr);
	time_t t;
	ഘടന stat fst;

	എങ്കിൽ (geteuid() != 0)
		തിരികെ;
	എങ്കിൽ ((fd = open(_PATH_BTMP, O_WRONLY | O_APPEND)) < 0) {
		debug("Unable to open the btmp file %s: %s", _PATH_BTMP,
		    strerror(errno));
		തിരികെ;
	}
	എങ്കിൽ (fstat(fd, &fst) < 0) {
		logit("%s: fstat of %s failed: %s", __func__, _PATH_BTMP,
		    strerror(errno));
		പോകുക out;
	}
	എങ്കിൽ ((fst.st_mode & (S_IXGRP | S_IRWXO)) || fst.st_uid != 0) {
		logit("Excess permission or bad ownership on file %s",
		    _PATH_BTMP);
		പോകുക out;
	}

	/* Construct a logininfo and turn it into a utmp */
	memset(&li, 0, വലുപ്പം(li));
	li.type = LTYPE_FAILED;
	li.pid = getpid();
	strlcpy(li.വരി, "ssh:notty", വലുപ്പം(li.വരി));
	strlcpy(li.username, username, വലുപ്പം(li.username));
	strlcpy(li.hostname, hostname, വലുപ്പം(li.hostname));
	time(&t);
	li.tv_sec = t > 0 ? (unsigned long)t : 0;
	എങ്കിൽ (ssh_packet_connection_is_on_socket(ssh)) {
		(ശൂന്യം)getpeername(ssh_packet_get_connection_in(ssh),
		    &li.hostaddr.sa, &fromlen);
	}
	construct_utmp(&li, &ut);

	എങ്കിൽ (atomicio(vwrite, fd, &ut, വലുപ്പം(ut)) != വലുപ്പം(ut)) {
		error("Failed to write to %s: %s", _PATH_BTMP,
		    strerror(errno));
	}
out:
	close(fd);
}
#endif	/* USE_BTMP */
