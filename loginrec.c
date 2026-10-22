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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/time.h>

#అన్తర్భావ <netinet/in.h>

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "loginrec.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "misc.h"

# include <util.h>

#నిర్వచితమైతే USE_WTMPDB
# include <wtmpdb.h>
#అయితే_ముగింపు

/**
 ** prototypes for helper functions in this file
 **/

#ఒకవేళ HAVE_UTMP_H
శూన్య సమితి_utmp_సమయం(నిర్మాణం logininfo *li, నిర్మాణం utmp *ut);
శూన్య construct_utmp(నిర్మాణం logininfo *li, నిర్మాణం utmp *ut);
#అయితే_ముగింపు

#నిర్వచితమైతే HAVE_UTMPX_H
శూన్య సమితి_utmpx_సమయం(నిర్మాణం logininfo *li, నిర్మాణం utmpx *ut);
శూన్య construct_utmpx(నిర్మాణం logininfo *li, నిర్మాణం utmpx *ut);
#అయితే_ముగింపు

పూర్ణాంకం utmp_write_నమోదు(నిర్మాణం logininfo *li);
పూర్ణాంకం utmpx_write_నమోదు(నిర్మాణం logininfo *li);
పూర్ణాంకం wtmp_write_నమోదు(నిర్మాణం logininfo *li);
పూర్ణాంకం wtmpx_write_నమోదు(నిర్మాణం logininfo *li);
పూర్ణాంకం lastlog_write_నమోదు(నిర్మాణం logininfo *li);
పూర్ణాంకం syslogin_write_నమోదు(నిర్మాణం logininfo *li);
#నిర్వచితమైతే USE_WTMPDB
పూర్ణాంకం wtmpdb_write_నమోదు(నిర్మాణం logininfo *li);
#అయితే_ముగింపు

పూర్ణాంకం getlast_నమోదు(నిర్మాణం logininfo *li);
పూర్ణాంకం lastlog_get_నమోదు(నిర్మాణం logininfo *li);
పూర్ణాంకం utmpx_get_నమోదు(నిర్మాణం logininfo *li);
పూర్ణాంకం wtmp_get_నమోదు(నిర్మాణం logininfo *li);
పూర్ణాంకం wtmpx_get_నమోదు(నిర్మాణం logininfo *li);

బాహ్య నిర్మాణం sshbuf *loginmsg;

/* pick the shortest string */
#నిర్వచించు MIN_SIZEOF(s1,s2) (పరిమాణం(s1) < పరిమాణం(s2) ? పరిమాణం(s1) : పరిమాణం(s2))

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
పూర్ణాంకం
login_login(నిర్మాణం logininfo *li)
{
	li->type = LTYPE_LOGIN;
	తిరిగి (login_write(li));
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
పూర్ణాంకం
login_logout(నిర్మాణం logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	తిరిగి (login_write(li));
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
గుర్తులేని పూర్ణాంకం
login_get_lastlog_సమయం(స్థిరరాశి uid_t uid)
{
	నిర్మాణం logininfo li;

	ఒకవేళ (login_get_lastlog(&li, uid))
		తిరిగి (li.tv_sec);
	లేకపోతే
		తిరిగి (0);
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
నిర్మాణం logininfo *
login_get_lastlog(నిర్మాణం logininfo *li, స్థిరరాశి uid_t uid)
{
	నిర్మాణం passwd *pw;

	memset(li, '\0', పరిమాణం(*li));
	li->uid = uid;

	/*
	 * If we don't have a 'real' lastlog, we need the username to
	 * reliably search wtmp(x) for the last login (see
	 * wtmp_get_entry().)
	 */
	pw = getpwuid(uid);
	ఒకవేళ (pw == ఖాళీ)
		fatal("%s: Cannot find account for uid %ld", __func__,
		    (దీర్ఘ)uid);

	ఒకవేళ (strlcpy(li->username, pw->pw_name, పరిమాణం(li->username)) >=
	    పరిమాణం(li->username)) {
		error("%s: username too long (%lu > max %lu)", __func__,
		    (గుర్తులేని దీర్ఘ)అక్షరశ్రేణి_పొడవు(pw->pw_name),
		    (గుర్తులేని దీర్ఘ)పరిమాణం(li->username) - 1);
		తిరిగి ఖాళీ;
	}

	ఒకవేళ (getlast_నమోదు(li))
		తిరిగి (li);
	లేకపోతే
		తిరిగి (ఖాళీ);
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
నిర్మాణం
logininfo *login_alloc_నమోదు(pid_t pid, స్థిరరాశి అక్షరం *username,
    స్థిరరాశి అక్షరం *hostname, స్థిరరాశి అక్షరం *పంక్తి)
{
	నిర్మాణం logininfo *newli;

	newli = xmalloc(పరిమాణం(*newli));
	login_init_నమోదు(newli, pid, username, hostname, పంక్తి);
	తిరిగి (newli);
}


/* login_free_entry(struct logininfo *)    - free struct memory */
శూన్య
login_free_నమోదు(నిర్మాణం logininfo *li)
{
	విడుదల(li);
}


/* login_init_entry(struct logininfo *, int, char*, char*, char*)
 *                                        - initialise a struct logininfo
 *
 * Populates a new struct logininfo, a data structure meant to carry
 * the information required to portably record login info.
 *
 * Returns: 1
 */
పూర్ణాంకం
login_init_నమోదు(నిర్మాణం logininfo *li, pid_t pid, స్థిరరాశి అక్షరం *username,
    స్థిరరాశి అక్షరం *hostname, స్థిరరాశి అక్షరం *పంక్తి)
{
	నిర్మాణం passwd *pw;

	memset(li, 0, పరిమాణం(*li));

	li->pid = pid;

	/* set the line information */
	ఒకవేళ (పంక్తి)
		పంక్తి_fullname(li->పంక్తి, పంక్తి, పరిమాణం(li->పంక్తి));

	ఒకవేళ (username) {
		strlcpy(li->username, username, పరిమాణం(li->username));
		pw = getpwnam(li->username);
		ఒకవేళ (pw == ఖాళీ) {
			fatal("%s: Cannot find user \"%s\"", __func__,
			    li->username);
		}
		li->uid = pw->pw_uid;
	}

	ఒకవేళ (hostname)
		strlcpy(li->hostname, hostname, పరిమాణం(li->hostname));

	తిరిగి (1);
}

/*
 * login_set_current_time(struct logininfo *)    - set the current time
 *
 * Set the current time in a logininfo structure. This function is
 * meant to eliminate the need to deal with system dependencies for
 * time handling.
 */
శూన్య
login_సమితి_current_సమయం(నిర్మాణం logininfo *li)
{
	నిర్మాణం timeval tv;

	gettimeofday(&tv, ఖాళీ);

	li->tv_sec = tv.tv_sec;
	li->tv_usec = tv.tv_usec;
}

/* copy a sockaddr_* into our logininfo */
శూన్య
login_సమితి_addr(నిర్మాణం logininfo *li, స్థిరరాశి నిర్మాణం sockaddr *sa,
    స్థిరరాశి గుర్తులేని పూర్ణాంకం sa_కొలత)
{
	గుర్తులేని పూర్ణాంకం bufsize = sa_కొలత;

	/* make sure we don't overrun our union */
	ఒకవేళ (పరిమాణం(li->hostaddr) < sa_కొలత)
		bufsize = పరిమాణం(li->hostaddr);

	జ్ఞాపకం_నకలు(&li->hostaddr.sa, sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/
పూర్ణాంకం
login_write(నిర్మాణం logininfo *li)
{
#నిర్వచితం_కాకపోతే HAVE_CYGWIN
	ఒకవేళ (geteuid() != 0) {
		logit("Attempt to write login records by non-root user (aborting)");
		తిరిగి (1);
	}
#అయితే_ముగింపు

	/* set the timestamp */
	login_సమితి_current_సమయం(li);
#నిర్వచితమైతే USE_LOGIN
	syslogin_write_నమోదు(li);
#అయితే_ముగింపు
#నిర్వచితమైతే USE_LASTLOG
	ఒకవేళ (li->type == LTYPE_LOGIN)
		lastlog_write_నమోదు(li);
#అయితే_ముగింపు
#నిర్వచితమైతే USE_UTMP
	utmp_write_నమోదు(li);
#అయితే_ముగింపు
#నిర్వచితమైతే USE_WTMP
	wtmp_write_నమోదు(li);
#అయితే_ముగింపు
#నిర్వచితమైతే USE_UTMPX
	utmpx_write_నమోదు(li);
#అయితే_ముగింపు
#నిర్వచితమైతే USE_WTMPX
	wtmpx_write_నమోదు(li);
#అయితే_ముగింపు
#నిర్వచితమైతే USE_WTMPDB
	wtmpdb_write_నమోదు(li);
#అయితే_ముగింపు
#నిర్వచితమైతే CUSTOM_SYS_AUTH_రికార్డు_LOGIN
	ఒకవేళ (li->type == LTYPE_LOGIN &&
	    !sys_auth_రికార్డు_login(li->username,li->hostname,li->పంక్తి,
	    loginmsg))
		logit("Writing login record failed for %s", li->username);
#అయితే_ముగింపు
#నిర్వచితమైతే SSH_AUDIT_EVENTS
	ఒకవేళ (li->type == LTYPE_LOGIN)
		audit_session_open(li);
	లేకపోతే ఒకవేళ (li->type == LTYPE_LOGOUT)
		audit_session_close(li);
#అయితే_ముగింపు
	తిరిగి (0);
}

#నిర్వచితమైతే LOGIN_NEEDS_UTMPX
పూర్ణాంకం
login_utmp_only(నిర్మాణం logininfo *li)
{
	li->type = LTYPE_LOGIN;
	login_సమితి_current_సమయం(li);
# ifdef USE_UTMP
	utmp_write_నమోదు(li);
# endif
# ifdef USE_WTMP
	wtmp_write_నమోదు(li);
# endif
# ifdef USE_UTMPX
	utmpx_write_నమోదు(li);
# endif
# ifdef USE_WTMPX
	wtmpx_write_నమోదు(li);
# endif
	తిరిగి (0);
}
#అయితే_ముగింపు

/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
పూర్ణాంకం
getlast_నమోదు(నిర్మాణం logininfo *li)
{
#నిర్వచితమైతే USE_LASTLOG
	తిరిగి(lastlog_get_నమోదు(li));
#లేకపోతే /* !USE_LASTLOG */
#ఒకవేళ defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
	తిరిగి (utmpx_get_నమోదు(li));
#అయితే_ముగింపు

#ఒకవేళ defined(DISABLE_LASTLOG)
	/* On some systems we shouldn't even try to obtain last login
	 * time, e.g. AIX */
	తిరిగి (0);
# elif defined(USE_WTMP) && \
    (defined(HAVE_సమయం_లోపల_UTMP) || defined(HAVE_TV_లోపల_UTMP))
	/* retrieve last login time from utmp */
	తిరిగి (wtmp_get_నమోదు(li));
# elif defined(USE_WTMPX) && \
    (defined(HAVE_సమయం_లోపల_UTMPX) || defined(HAVE_TV_లోపల_UTMPX))
	/* If wtmp isn't available, try wtmpx */
	తిరిగి (wtmpx_get_నమోదు(li));
# లేకపోతే
	/* Give up: No means of retrieving last login time */
	తిరిగి (0);
# endif /* DISABLE_LASTLOG */
#అయితే_ముగింపు /* USE_LASTLOG */
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
అక్షరం *
పంక్తి_fullname(అక్షరం *dst, స్థిరరాశి అక్షరం *src, u_int dstsize)
{
	memset(dst, '\0', dstsize);
	ఒకవేళ ((అక్షరశ్రేణి_పోలిక(src, "/dev/", 5) == 0) || (dstsize < (అక్షరశ్రేణి_పొడవు(src) + 5)))
		strlcpy(dst, src, dstsize);
	లేకపోతే {
		strlcpy(dst, "/dev/", dstsize);
		strlcat(dst, src, dstsize);
	}
	తిరిగి (dst);
}

/* line_stripname(): strip the leading '/dev' if it exists, return dst */
అక్షరం *
పంక్తి_stripname(అక్షరం *dst, స్థిరరాశి అక్షరం *src, పూర్ణాంకం dstsize)
{
	memset(dst, '\0', dstsize);
	ఒకవేళ (అక్షరశ్రేణి_పోలిక(src, "/dev/", 5) == 0)
		strlcpy(dst, src + 5, dstsize);
	లేకపోతే
		strlcpy(dst, src, dstsize);
	తిరిగి (dst);
}

/*
 * line_abbrevname(): Return the abbreviated (usually four-character)
 * form of the line (Just use the last <dstsize> characters of the
 * full name.)
 *
 * NOTE: use strncpy because we do NOT necessarily want zero
 * termination
 */
అక్షరం *
పంక్తి_abbrevname(అక్షరం *dst, స్థిరరాశి అక్షరం *src, పూర్ణాంకం dstsize)
{
	కొలత_t len;

	memset(dst, '\0', dstsize);

	ఒకవేళ (strcmp(src, "ssh:notty") == 0)
		తిరిగి dst;

	/* Always skip prefix if present */
	ఒకవేళ (అక్షరశ్రేణి_పోలిక(src, "/dev/", 5) == 0)
		src += 5;

#నిర్వచితమైతే WITH_ABBREV_NO_TTY
	ఒకవేళ (అక్షరశ్రేణి_పోలిక(src, "tty", 3) == 0)
		src += 3;
#అయితే_ముగింపు

	len = అక్షరశ్రేణి_పొడవు(src);

	ఒకవేళ (len > 0) {
		ఒకవేళ (((పూర్ణాంకం)len - dstsize) > 0)
			src +=  ((పూర్ణాంకం)len - dstsize);

		/* note: _don't_ change this to strlcpy */
		strncpy(dst, src, (కొలత_t)dstsize);
	}

	తిరిగి (dst);
}

/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#ఒకవేళ defined(USE_BTMP) || defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
శూన్య
సమితి_utmp_సమయం(నిర్మాణం logininfo *li, నిర్మాణం utmp *ut)
{
# ఒకవేళ defined(HAVE_TV_లోపల_UTMP)
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_సమయం_లోపల_UTMP)
	ut->ut_సమయం = li->tv_sec;
# endif
}

శూన్య
construct_utmp(నిర్మాణం logininfo *li,
		    నిర్మాణం utmp *ut)
{
# ifdef HAVE_ADDR_V6_లోపల_UTMP
	నిర్మాణం sockaddr_in6 *sa6;
# endif

	memset(ut, '\0', పరిమాణం(*ut));

	/* First fill out fields used for both logins and logouts */

# ifdef HAVE_ID_లోపల_UTMP
	పంక్తి_abbrevname(ut->ut_id, li->పంక్తి, పరిమాణం(ut->ut_id));
# endif

# ifdef HAVE_TYPE_లోపల_UTMP
	/* This is done here to keep utmp constants out of struct logininfo */
	ఎంపిక (li->type) {
	స్థితి LTYPE_FAILED:
		ut->ut_type = LOGIN_PROCESS;
		ఆపు;
	స్థితి LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		ఆపు;
	స్థితి LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		ఆపు;
	}
# endif
	సమితి_utmp_సమయం(li, ut);

	పంక్తి_stripname(ut->ut_పంక్తి, li->పంక్తి, పరిమాణం(ut->ut_పంక్తి));

# ifdef HAVE_PID_లోపల_UTMP
	ut->ut_pid = li->pid;
# endif

	/* If we're logging out, leave all other fields blank */
	ఒకవేళ (li->type == LTYPE_LOGOUT)
		తిరిగి;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

	/* Use strncpy because we don't necessarily want null termination */
	strncpy(ut->ut_name, li->username,
	    MIN_SIZEOF(ut->ut_name, li->username));
# ifdef HAVE_HOST_లోపల_UTMP
	strncpy(ut->ut_host, li->hostname,
	    MIN_SIZEOF(ut->ut_host, li->hostname));
# endif
# ifdef HAVE_ADDR_లోపల_UTMP
	/* this is just a 32-bit IP address */
	ఒకవేళ (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_లోపల.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_లోపల_UTMP
	/* this is just a 128-bit IPv6 address */
	ఒకవేళ (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((నిర్మాణం sockaddr_in6 *)&li->hostaddr.sa);
		జ్ఞాపకం_నకలు(ut->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		ఒకవేళ (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			ut->ut_addr_v6[0] = ut->ut_addr_v6[3];
			ut->ut_addr_v6[1] = 0;
			ut->ut_addr_v6[2] = 0;
			ut->ut_addr_v6[3] = 0;
		}
	}
# endif
}
#అయితే_ముగింపు /* USE_BTMP || USE_UTMP || USE_WTMP || USE_LOGIN */

/**
 ** utmpx utility functions
 **
 ** These functions manipulate struct utmpx, accounting for system
 ** variations.
 **/

#ఒకవేళ defined(USE_UTMPX) || defined (USE_WTMPX)
/* build the utmpx structure */
శూన్య
సమితి_utmpx_సమయం(నిర్మాణం logininfo *li, నిర్మాణం utmpx *utx)
{
# ఒకవేళ defined(HAVE_TV_లోపల_UTMPX)
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_సమయం_లోపల_UTMPX)
	utx->ut_సమయం = li->tv_sec;
# endif
}

శూన్య
construct_utmpx(నిర్మాణం logininfo *li, నిర్మాణం utmpx *utx)
{
# ifdef HAVE_ADDR_V6_లోపల_UTMPX
	నిర్మాణం sockaddr_in6 *sa6;
#  endif
	memset(utx, '\0', పరిమాణం(*utx));

# ifdef HAVE_ID_లోపల_UTMPX
	పంక్తి_abbrevname(utx->ut_id, li->పంక్తి, పరిమాణం(utx->ut_id));
# endif

	/* this is done here to keep utmp constants out of loginrec.h */
	ఎంపిక (li->type) {
	స్థితి LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		ఆపు;
	స్థితి LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		ఆపు;
	}
	పంక్తి_stripname(utx->ut_పంక్తి, li->పంక్తి, పరిమాణం(utx->ut_పంక్తి));
	సమితి_utmpx_సమయం(li, utx);
	utx->ut_pid = li->pid;

	/* strncpy(): Don't necessarily want null termination */
	strncpy(utx->ut_user, li->username,
	    MIN_SIZEOF(utx->ut_user, li->username));

	ఒకవేళ (li->type == LTYPE_LOGOUT)
		తిరిగి;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

# ifdef HAVE_HOST_లోపల_UTMPX
	strncpy(utx->ut_host, li->hostname,
	    MIN_SIZEOF(utx->ut_host, li->hostname));
# endif
# ifdef HAVE_SS_లోపల_UTMPX
	utx->ut_ss = li->hostaddr.sa_storage;
# endif
# ifdef HAVE_ADDR_లోపల_UTMPX
	/* this is just a 32-bit IP address */
	ఒకవేళ (li->hostaddr.sa.sa_family == AF_INET)
		utx->ut_addr = li->hostaddr.sa_లోపల.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_లోపల_UTMPX
	/* this is just a 128-bit IPv6 address */
	ఒకవేళ (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((నిర్మాణం sockaddr_in6 *)&li->hostaddr.sa);
		జ్ఞాపకం_నకలు(utx->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		ఒకవేళ (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			utx->ut_addr_v6[0] = utx->ut_addr_v6[3];
			utx->ut_addr_v6[1] = 0;
			utx->ut_addr_v6[2] = 0;
			utx->ut_addr_v6[3] = 0;
		}
	}
# endif
# ifdef HAVE_SYSLEN_లోపల_UTMPX
	/* ut_syslen is the length of the utx_host string */
	utx->ut_syslen = MINIMUM(అక్షరశ్రేణి_పొడవు(li->hostname), పరిమాణం(utx->ut_host));
# endif
}
#అయితే_ముగింపు /* USE_UTMPX || USE_WTMPX */

/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */
#నిర్వచితమైతే USE_UTMP

/* if we can, use pututline() etc. */
# ఒకవేళ !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
	defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
# endif


/* write a utmp entry with the system's help (pututline() and pals) */
# ifdef UTMP_USE_LIBRARY
స్థిర పూర్ణాంకం
utmp_write_library(నిర్మాణం logininfo *li, నిర్మాణం utmp *ut)
{
	setutent();
	pututline(ut);
#  ifdef HAVE_ENDUTENT
	endutent();
#  endif
	తిరిగి (1);
}
# లేకపోతే /* UTMP_USE_LIBRARY */

/*
 * Write a utmp entry direct to the file
 * This is a slightly modification of code in OpenBSD's login.c
 */
స్థిర పూర్ణాంకం
utmp_write_ప్రత్యక్ష(నిర్మాణం logininfo *li, నిర్మాణం utmp *ut)
{
	నిర్మాణం utmp old_ut;
	నమోదు పూర్ణాంకం fd;
	పూర్ణాంకం tty;

	/* FIXME: (ATL) ttyslot() needs local implementation */

#ఒకవేళ defined(HAVE_GETTTYENT)
	నిర్మాణం ttyent *ty;

	tty=0;
	setttyent();
	అయితే (ఖాళీ != (ty = getttyent())) {
		tty++;
		ఒకవేళ (!అక్షరశ్రేణి_పోలిక(ty->ty_name, ut->ut_పంక్తి, పరిమాణం(ut->ut_పంక్తి)))
			ఆపు;
	}
	endttyent();

	ఒకవేళ (ఖాళీ == ty) {
		logit_f("tty not found");
		తిరిగి (0);
	}
#లేకపోతే /* FIXME */

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

#అయితే_ముగింపు /* HAVE_GETTTYENT */

	ఒకవేళ (tty > 0 && (fd = open(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		off_t pos, ret;

		pos = (off_t)tty * పరిమాణం(నిర్మాణం utmp);
		ఒకవేళ ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			తిరిగి (0);
		}
		ఒకవేళ (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			తిరిగి (0);
		}
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		ఒకవేళ (atomicio(పఠ, fd, &old_ut, పరిమాణం(old_ut)) == పరిమాణం(old_ut) &&
		    (ut->ut_host[0] == '\0') && (old_ut.ut_host[0] != '\0') &&
		    (అక్షరశ్రేణి_పోలిక(old_ut.ut_పంక్తి, ut->ut_పంక్తి, పరిమాణం(ut->ut_పంక్తి)) == 0) &&
		    (అక్షరశ్రేణి_పోలిక(old_ut.ut_name, ut->ut_name, పరిమాణం(ut->ut_name)) == 0))
			జ్ఞాపకం_నకలు(ut->ut_host, old_ut.ut_host, పరిమాణం(ut->ut_host));

		ఒకవేళ ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			తిరిగి (0);
		}
		ఒకవేళ (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			తిరిగి (0);
		}
		ఒకవేళ (atomicio(vwrite, fd, ut, పరిమాణం(*ut)) != పరిమాణం(*ut)) {
			logit("%s: error writing %s: %s", __func__,
			    UTMP_FILE, strerror(errno));
			close(fd);
			తిరిగి (0);
		}

		close(fd);
		తిరిగి (1);
	} లేకపోతే {
		తిరిగి (0);
	}
}
# endif /* UTMP_USE_LIBRARY */

స్థిర పూర్ణాంకం
utmp_perform_login(నిర్మాణం logininfo *li)
{
	నిర్మాణం utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	ఒకవేళ (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		తిరిగి (0);
	}
# లేకపోతే
	ఒకవేళ (!utmp_write_ప్రత్యక్ష(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		తిరిగి (0);
	}
# endif
	తిరిగి (1);
}


స్థిర పూర్ణాంకం
utmp_perform_logout(నిర్మాణం logininfo *li)
{
	నిర్మాణం utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	ఒకవేళ (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		తిరిగి (0);
	}
# లేకపోతే
	ఒకవేళ (!utmp_write_ప్రత్యక్ష(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		తిరిగి (0);
	}
# endif
	తిరిగి (1);
}


పూర్ణాంకం
utmp_write_నమోదు(నిర్మాణం logininfo *li)
{
	ఎంపిక(li->type) {
	స్థితి LTYPE_LOGIN:
		తిరిగి (utmp_perform_login(li));

	స్థితి LTYPE_LOGOUT:
		తిరిగి (utmp_perform_logout(li));

	అప్రమేయ:
		logit_f("invalid type field");
		తిరిగి (0);
	}
}
#అయితే_ముగింపు /* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#నిర్వచితమైతే USE_UTMPX

/* if we have the wherewithal, use pututxline etc. */
# ఒకవేళ !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) && \
	defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
# endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
# ifdef UTMPX_USE_LIBRARY
స్థిర పూర్ణాంకం
utmpx_write_library(నిర్మాణం logininfo *li, నిర్మాణం utmpx *utx)
{
	setutxent();
	pututxline(utx);

#  ifdef HAVE_ENDUTXENT
	endutxent();
#  endif
	తిరిగి (1);
}

# లేకపోతే /* UTMPX_USE_LIBRARY */

/* write a utmp entry direct to the file */
స్థిర పూర్ణాంకం
utmpx_write_ప్రత్యక్ష(నిర్మాణం logininfo *li, నిర్మాణం utmpx *utx)
{
	logit_f("not implemented!");
	తిరిగి (0);
}
# endif /* UTMPX_USE_LIBRARY */

స్థిర పూర్ణాంకం
utmpx_perform_login(నిర్మాణం logininfo *li)
{
	నిర్మాణం utmpx utx;

	construct_utmpx(li, &utx);
# ifdef UTMPX_USE_LIBRARY
	ఒకవేళ (!utmpx_write_library(li, &utx)) {
		logit_f("utmp_write_library() failed");
		తిరిగి (0);
	}
# లేకపోతే
	ఒకవేళ (!utmpx_write_ప్రత్యక్ష(li, &utx)) {
		logit_f("utmp_write_direct() failed");
		తిరిగి (0);
	}
# endif
	తిరిగి (1);
}


స్థిర పూర్ణాంకం
utmpx_perform_logout(నిర్మాణం logininfo *li)
{
	నిర్మాణం utmpx utx;

	construct_utmpx(li, &utx);
# ifdef HAVE_ID_లోపల_UTMPX
	పంక్తి_abbrevname(utx.ut_id, li->పంక్తి, పరిమాణం(utx.ut_id));
# endif
# ifdef HAVE_TYPE_లోపల_UTMPX
	utx.ut_type = DEAD_PROCESS;
# endif

# ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
# లేకపోతే
	utmpx_write_ప్రత్యక్ష(li, &utx);
# endif
	తిరిగి (1);
}

పూర్ణాంకం
utmpx_write_నమోదు(నిర్మాణం logininfo *li)
{
	ఎంపిక(li->type) {
	స్థితి LTYPE_LOGIN:
		తిరిగి (utmpx_perform_login(li));
	స్థితి LTYPE_LOGOUT:
		తిరిగి (utmpx_perform_logout(li));
	అప్రమేయ:
		logit_f("invalid type field");
		తిరిగి (0);
	}
}
#అయితే_ముగింపు /* USE_UTMPX */


/**
 ** Low-level wtmp functions
 **/

#నిర్వచితమైతే USE_WTMP

/*
 * Write a wtmp entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
స్థిర పూర్ణాంకం
wtmp_write(నిర్మాణం logininfo *li, నిర్మాణం utmp *ut)
{
	నిర్మాణం stat buf;
	పూర్ణాంకం fd, ret = 1;

	ఒకవేళ ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem writing %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		తిరిగి (0);
	}
	ఒకవేళ (fstat(fd, &buf) == 0)
		ఒకవేళ (atomicio(vwrite, fd, ut, పరిమాణం(*ut)) != పరిమాణం(*ut)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMP_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);
	తిరిగి (ret);
}

స్థిర పూర్ణాంకం
wtmp_perform_login(నిర్మాణం logininfo *li)
{
	నిర్మాణం utmp ut;

	construct_utmp(li, &ut);
	తిరిగి (wtmp_write(li, &ut));
}


స్థిర పూర్ణాంకం
wtmp_perform_logout(నిర్మాణం logininfo *li)
{
	నిర్మాణం utmp ut;

	construct_utmp(li, &ut);
	తిరిగి (wtmp_write(li, &ut));
}


పూర్ణాంకం
wtmp_write_నమోదు(నిర్మాణం logininfo *li)
{
	ఎంపిక(li->type) {
	స్థితి LTYPE_LOGIN:
		తిరిగి (wtmp_perform_login(li));
	స్థితి LTYPE_LOGOUT:
		తిరిగి (wtmp_perform_logout(li));
	అప్రమేయ:
		logit_f("invalid type field");
		తిరిగి (0);
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
స్థిర పూర్ణాంకం
wtmp_islogin(నిర్మాణం logininfo *li, నిర్మాణం utmp *ut)
{
	ఒకవేళ (అక్షరశ్రేణి_పోలిక(li->username, ut->ut_name,
	    MIN_SIZEOF(li->username, ut->ut_name)) == 0) {
# ifdef HAVE_TYPE_లోపల_UTMP
		ఒకవేళ (ut->ut_type & USER_PROCESS)
			తిరిగి (1);
# లేకపోతే
		తిరిగి (1);
# endif
	}
	తిరిగి (0);
}

పూర్ణాంకం
wtmp_get_నమోదు(నిర్మాణం logininfo *li)
{
	నిర్మాణం stat st;
	నిర్మాణం utmp ut;
	పూర్ణాంకం fd, దొరికింది = 0;

	/* Clear the time entries in our logininfo */
	li->tv_sec = li->tv_usec = 0;

	ఒకవేళ ((fd = open(WTMP_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		తిరిగి (0);
	}
	ఒకవేళ (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		close(fd);
		తిరిగి (0);
	}

	/* Seek to the start of the last struct utmp */
	ఒకవేళ (lseek(fd, -(off_t)పరిమాణం(నిర్మాణం utmp), SEEK_END) == -1) {
		/* Looks like we've got a fresh wtmp file */
		close(fd);
		తిరిగి (0);
	}

	అయితే (!దొరికింది) {
		ఒకవేళ (atomicio(పఠ, fd, &ut, పరిమాణం(ut)) != పరిమాణం(ut)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMP_FILE, strerror(errno));
			close (fd);
			తిరిగి (0);
		}
		ఒకవేళ (wtmp_islogin(li, &ut) ) {
			దొరికింది = 1;
			/*
			 * We've already checked for a time in struct
			 * utmp, in login_getlast()
			 */
# ifdef HAVE_సమయం_లోపల_UTMP
			li->tv_sec = ut.ut_సమయం;
# లేకపోతే
#  ఒకవేళ HAVE_TV_లోపల_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
# endif
			పంక్తి_fullname(li->పంక్తి, ut.ut_పంక్తి,
			    MIN_SIZEOF(li->పంక్తి, ut.ut_పంక్తి));
# ifdef HAVE_HOST_లోపల_UTMP
			strlcpy(li->hostname, ut.ut_host,
			    MIN_SIZEOF(li->hostname, ut.ut_host));
# endif
			కొనసాగు;
		}
		/* Seek back 2 x struct utmp */
		ఒకవేళ (lseek(fd, -(off_t)(2 * పరిమాణం(నిర్మాణం utmp)), SEEK_CUR) == -1) {
			/* We've found the start of the file, so quit */
			close(fd);
			తిరిగి (0);
		}
	}

	/* We found an entry. Tidy up and return */
	close(fd);
	తిరిగి (1);
}
# endif /* USE_WTMP */


/**
 ** Low-level wtmpx functions
 **/

#నిర్వచితమైతే USE_WTMPX
/*
 * Write a wtmpx entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
స్థిర పూర్ణాంకం
wtmpx_write(నిర్మాణం logininfo *li, నిర్మాణం utmpx *utx)
{
#నిర్వచితం_కాకపోతే HAVE_UPDWTMPX
	నిర్మాణం stat buf;
	పూర్ణాంకం fd, ret = 1;

	ఒకవేళ ((fd = open(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		తిరిగి (0);
	}

	ఒకవేళ (fstat(fd, &buf) == 0)
		ఒకవేళ (atomicio(vwrite, fd, utx, పరిమాణం(*utx)) != పరిమాణం(*utx)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);

	తిరిగి (ret);
#లేకపోతే
	updwtmpx(WTMPX_FILE, utx);
	తిరిగి (1);
#అయితే_ముగింపు
}


స్థిర పూర్ణాంకం
wtmpx_perform_login(నిర్మాణం logininfo *li)
{
	నిర్మాణం utmpx utx;

	construct_utmpx(li, &utx);
	తిరిగి (wtmpx_write(li, &utx));
}


స్థిర పూర్ణాంకం
wtmpx_perform_logout(నిర్మాణం logininfo *li)
{
	నిర్మాణం utmpx utx;

	construct_utmpx(li, &utx);
	తిరిగి (wtmpx_write(li, &utx));
}


పూర్ణాంకం
wtmpx_write_నమోదు(నిర్మాణం logininfo *li)
{
	ఎంపిక(li->type) {
	స్థితి LTYPE_LOGIN:
		తిరిగి (wtmpx_perform_login(li));
	స్థితి LTYPE_LOGOUT:
		తిరిగి (wtmpx_perform_logout(li));
	అప్రమేయ:
		logit_f("invalid type field");
		తిరిగి (0);
	}
}

/* Please see the notes above wtmp_islogin() for information about the
   next two functions */

/* Return true if this wtmpx entry indicates a login */
స్థిర పూర్ణాంకం
wtmpx_islogin(నిర్మాణం logininfo *li, నిర్మాణం utmpx *utx)
{
	ఒకవేళ (అక్షరశ్రేణి_పోలిక(li->username, utx->ut_user,
	    MIN_SIZEOF(li->username, utx->ut_user)) == 0 ) {
# ifdef HAVE_TYPE_లోపల_UTMPX
		ఒకవేళ (utx->ut_type == USER_PROCESS)
			తిరిగి (1);
# లేకపోతే
		తిరిగి (1);
# endif
	}
	తిరిగి (0);
}


పూర్ణాంకం
wtmpx_get_నమోదు(నిర్మాణం logininfo *li)
{
	నిర్మాణం stat st;
	నిర్మాణం utmpx utx;
	పూర్ణాంకం fd, దొరికింది=0;

	/* Clear the time entries */
	li->tv_sec = li->tv_usec = 0;

	ఒకవేళ ((fd = open(WTMPX_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		తిరిగి (0);
	}
	ఒకవేళ (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		close(fd);
		తిరిగి (0);
	}

	/* Seek to the start of the last struct utmpx */
	ఒకవేళ (lseek(fd, -(off_t)పరిమాణం(నిర్మాణం utmpx), SEEK_END) == -1 ) {
		/* probably a newly rotated wtmpx file */
		close(fd);
		తిరిగి (0);
	}

	అయితే (!దొరికింది) {
		ఒకవేళ (atomicio(పఠ, fd, &utx, పరిమాణం(utx)) != పరిమాణం(utx)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			close (fd);
			తిరిగి (0);
		}
		/*
		 * Logouts are recorded as a blank username on a particular
		 * line. So, we just need to find the username in struct utmpx
		 */
		ఒకవేళ (wtmpx_islogin(li, &utx)) {
			దొరికింది = 1;
# ఒకవేళ defined(HAVE_TV_లోపల_UTMPX)
			li->tv_sec = utx.ut_tv.tv_sec;
# elif defined(HAVE_సమయం_లోపల_UTMPX)
			li->tv_sec = utx.ut_సమయం;
# endif
			పంక్తి_fullname(li->పంక్తి, utx.ut_పంక్తి, పరిమాణం(li->పంక్తి));
# ఒకవేళ defined(HAVE_HOST_లోపల_UTMPX)
			strlcpy(li->hostname, utx.ut_host,
			    MIN_SIZEOF(li->hostname, utx.ut_host));
# endif
			కొనసాగు;
		}
		ఒకవేళ (lseek(fd, -(off_t)(2 * పరిమాణం(నిర్మాణం utmpx)), SEEK_CUR) == -1) {
			close(fd);
			తిరిగి (0);
		}
	}

	close(fd);
	తిరిగి (1);
}
#అయితే_ముగింపు /* USE_WTMPX */

#నిర్వచితమైతే USE_WTMPDB
స్థిర పూర్ణాంకం
wtmpdb_perform_login(నిర్మాణం logininfo *li)
{
	uint64_t login_సమయం = li->tv_sec * ((uint64_t) 1000000ULL) +
	    li->tv_usec;
	స్థిరరాశి అక్షరం *tty;

	ఒకవేళ (అక్షరశ్రేణి_పోలిక(li->పంక్తి, "/dev/", 5) == 0)
		tty = &(li->పంక్తి[5]);
	లేకపోతే
		tty = li->పంక్తి;

	li->wtmpdb_id = wtmpdb_login(ఖాళీ, USER_PROCESS, li->username,
	    login_సమయం, tty, li->hostname, 0, 0);

	ఒకవేళ (li->wtmpdb_id < 0)
		తిరిగి (0);

	తిరిగి (1);
}

స్థిర పూర్ణాంకం
wtmpdb_perform_logout(నిర్మాణం logininfo *li)
{
	uint64_t logout_సమయం = li->tv_sec * ((uint64_t) 1000000ULL) +
	   li->tv_usec;

	ఒకవేళ (li->wtmpdb_id == 0) {
		స్థిరరాశి అక్షరం *tty;

		ఒకవేళ (అక్షరశ్రేణి_పోలిక(li->పంక్తి, "/dev/", 5) == 0)
			tty = &(li->పంక్తి[5]);
		లేకపోతే
			tty = li->పంక్తి;

		li->wtmpdb_id = wtmpdb_get_id(ఖాళీ, tty, ఖాళీ);
	}
	wtmpdb_logout(ఖాళీ, li->wtmpdb_id, logout_సమయం, ఖాళీ);

	తిరిగి (1);
}

పూర్ణాంకం
wtmpdb_write_నమోదు(నిర్మాణం logininfo *li)
{
	ఎంపిక(li->type) {
	స్థితి LTYPE_LOGIN:
		తిరిగి (wtmpdb_perform_login(li));
	స్థితి LTYPE_LOGOUT:
		తిరిగి (wtmpdb_perform_logout(li));
	అప్రమేయ:
		logit_f("invalid type field");
		తిరిగి (0);
	}
}
#అయితే_ముగింపు

/**
 ** Low-level libutil login() functions
 **/

#నిర్వచితమైతే USE_LOGIN
స్థిర పూర్ణాంకం
syslogin_perform_login(నిర్మాణం logininfo *li)
{
	నిర్మాణం utmp *ut;

	ut = xmalloc(పరిమాణం(*ut));
	construct_utmp(li, ut);
	login(ut);
	విడుదల(ut);

	తిరిగి (1);
}

స్థిర పూర్ణాంకం
syslogin_perform_logout(నిర్మాణం logininfo *li)
{
# ifdef HAVE_LOGOUT
	అక్షరం పంక్తి[UT_LINESIZE];

	(శూన్య)పంక్తి_stripname(పంక్తి, li->పంక్తి, పరిమాణం(పంక్తి));

	ఒకవేళ (!logout(పంక్తి))
		logit_f("logout() returned an error");
#  ifdef HAVE_LOGWTMP
	లేకపోతే
		logwtmp(పంక్తి, "", "");
#  endif
	/* FIXME: (ATL - if the need arises) What to do if we have
	 * login, but no logout?  what if logout but no logwtmp? All
	 * routines are in libutil so they should all be there,
	 * but... */
# endif
	తిరిగి (1);
}

పూర్ణాంకం
syslogin_write_నమోదు(నిర్మాణం logininfo *li)
{
	ఎంపిక (li->type) {
	స్థితి LTYPE_LOGIN:
		తిరిగి (syslogin_perform_login(li));
	స్థితి LTYPE_LOGOUT:
		తిరిగి (syslogin_perform_logout(li));
	అప్రమేయ:
		logit_f("Invalid type field");
		తిరిగి (0);
	}
}
#అయితే_ముగింపు /* USE_LOGIN */

/* end of file log-syslogin.c */

/**
 ** Low-level lastlog functions
 **/

#నిర్వచితమైతే USE_LASTLOG

#ఒకవేళ !defined(LASTLOG_WRITE_PUTUTXLINE) || !defined(HAVE_GETLASTLOGXBYNAME)
/* open the file (using filemode) and seek to the login entry */
స్థిర పూర్ణాంకం
lastlog_openseek(నిర్మాణం logininfo *li, పూర్ణాంకం *fd, పూర్ణాంకం filemode)
{
	off_t స్థానభ్రంశం;
	అక్షరం lastlog_file[1024];
	నిర్మాణం stat st;

	ఒకవేళ (stat(LASTLOG_FILE, &st) != 0) {
		logit("%s: Couldn't stat %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		తిరిగి (0);
	}
	ఒకవేళ (S_ISDIR(st.st_mode)) {
		snprintf(lastlog_file, పరిమాణం(lastlog_file), "%s/%s",
		    LASTLOG_FILE, li->username);
	} లేకపోతే ఒకవేళ (S_ISREG(st.st_mode)) {
		strlcpy(lastlog_file, LASTLOG_FILE, పరిమాణం(lastlog_file));
	} లేకపోతే {
		logit("%s: %.100s is not a file or directory!", __func__,
		    LASTLOG_FILE);
		తిరిగి (0);
	}

	*fd = open(lastlog_file, filemode, 0600);
	ఒకవేళ (*fd < 0) {
		debug("%s: Couldn't open %s: %s", __func__,
		    lastlog_file, strerror(errno));
		తిరిగి (0);
	}

	ఒకవేళ (S_ISREG(st.st_mode)) {
		/* find this uid's offset in the lastlog file */
		స్థానభ్రంశం = (off_t) ((u_long)li->uid * పరిమాణం(నిర్మాణం lastlog));

		ఒకవేళ (lseek(*fd, స్థానభ్రంశం, SEEK_SET) != స్థానభ్రంశం) {
			logit("%s: %s->lseek(): %s", __func__,
			    lastlog_file, strerror(errno));
			close(*fd);
			తిరిగి (0);
		}
	}

	తిరిగి (1);
}
#అయితే_ముగింపు /* !LASTLOG_WRITE_PUTUTXLINE || !HAVE_GETLASTLOGXBYNAME */

#నిర్వచితమైతే LASTLOG_WRITE_PUTUTXLINE
పూర్ణాంకం
lastlog_write_నమోదు(నిర్మాణం logininfo *li)
{
	ఎంపిక(li->type) {
	స్థితి LTYPE_LOGIN:
		తిరిగి 1; /* lastlog written by pututxline */
	అప్రమేయ:
		logit("lastlog_write_entry: Invalid type field");
		తిరిగి 0;
	}
}
#లేకపోతే /* LASTLOG_WRITE_PUTUTXLINE */
పూర్ణాంకం
lastlog_write_నమోదు(నిర్మాణం logininfo *li)
{
	నిర్మాణం lastlog చివరి;
	పూర్ణాంకం fd;

	ఎంపిక(li->type) {
	స్థితి LTYPE_LOGIN:
		/* create our struct lastlog */
		memset(&చివరి, '\0', పరిమాణం(చివరి));
		పంక్తి_stripname(చివరి.ll_పంక్తి, li->పంక్తి, పరిమాణం(చివరి.ll_పంక్తి));
		strlcpy(చివరి.ll_host, li->hostname,
		    MIN_SIZEOF(చివరి.ll_host, li->hostname));
		చివరి.ll_సమయం = li->tv_sec;

		ఒకవేళ (!lastlog_openseek(li, &fd, O_RDWR|O_CREAT))
			తిరిగి (0);

		/* write the entry */
		ఒకవేళ (atomicio(vwrite, fd, &చివరి, పరిమాణం(చివరి)) != పరిమాణం(చివరి)) {
			close(fd);
			logit("%s: Error writing to %s: %s", __func__,
			    LASTLOG_FILE, strerror(errno));
			తిరిగి (0);
		}

		close(fd);
		తిరిగి (1);
	అప్రమేయ:
		logit_f("Invalid type field");
		తిరిగి (0);
	}
}
#అయితే_ముగింపు /* LASTLOG_WRITE_PUTUTXLINE */

#నిర్వచితమైతే HAVE_GETLASTLOGXBYNAME
పూర్ణాంకం
lastlog_get_నమోదు(నిర్మాణం logininfo *li)
{
	నిర్మాణం lastlogx l, *ll;

	ఒకవేళ ((ll = getlastlogxbyname(li->username, &l)) == ఖాళీ) {
		memset(&l, '\0', పరిమాణం(l));
		ll = &l;
	}
	పంక్తి_fullname(li->పంక్తి, ll->ll_పంక్తి, పరిమాణం(li->పంక్తి));
	strlcpy(li->hostname, ll->ll_host,
		MIN_SIZEOF(li->hostname, ll->ll_host));
	li->tv_sec = ll->ll_tv.tv_sec;
	li->tv_usec = ll->ll_tv.tv_usec;
	తిరిగి (1);
}
#లేకపోతే /* HAVE_GETLASTLOGXBYNAME */
పూర్ణాంకం
lastlog_get_నమోదు(నిర్మాణం logininfo *li)
{
	నిర్మాణం lastlog చివరి;
	పూర్ణాంకం fd, ret;

	ఒకవేళ (!lastlog_openseek(li, &fd, O_RDONLY))
		తిరిగి (0);

	ret = atomicio(పఠ, fd, &చివరి, పరిమాణం(చివరి));
	close(fd);

	ఎంపిక (ret) {
	స్థితి 0:
		memset(&చివరి, '\0', పరిమాణం(చివరి));
		/* FALLTHRU */
	స్థితి పరిమాణం(చివరి):
		పంక్తి_fullname(li->పంక్తి, చివరి.ll_పంక్తి, పరిమాణం(li->పంక్తి));
		strlcpy(li->hostname, చివరి.ll_host,
		    MIN_SIZEOF(li->hostname, చివరి.ll_host));
		li->tv_sec = చివరి.ll_సమయం;
		తిరిగి (1);
	స్థితి -1:
		error("%s: Error reading from %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		తిరిగి (0);
	అప్రమేయ:
		error("%s: Error reading from %s: Expecting %d, got %d",
		    __func__, LASTLOG_FILE, (పూర్ణాంకం)పరిమాణం(చివరి), ret);
		తిరిగి (0);
	}

	/* NOTREACHED */
	తిరిగి (0);
}
#అయితే_ముగింపు /* HAVE_GETLASTLOGXBYNAME */
#అయితే_ముగింపు /* USE_LASTLOG */

#ఒకవేళ defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
పూర్ణాంకం
utmpx_get_నమోదు(నిర్మాణం logininfo *li)
{
	నిర్మాణం utmpx *utx;

	ఒకవేళ (setutxdb(UTXDB_LASTLOGIN, ఖాళీ) != 0)
		తిరిగి (0);
	utx = getutxuser(li->username);
	ఒకవేళ (utx == ఖాళీ) {
		endutxent();
		తిరిగి (0);
	}

	పంక్తి_fullname(li->పంక్తి, utx->ut_పంక్తి,
	    MIN_SIZEOF(li->పంక్తి, utx->ut_పంక్తి));
	strlcpy(li->hostname, utx->ut_host,
	    MIN_SIZEOF(li->hostname, utx->ut_host));
	li->tv_sec = utx->ut_tv.tv_sec;
	li->tv_usec = utx->ut_tv.tv_usec;
	endutxent();
	తిరిగి (1);
}
#అయితే_ముగింపు /* USE_UTMPX && HAVE_SETUTXDB && UTXDB_LASTLOGIN && HAVE_GETUTXUSER */

#నిర్వచితమైతే USE_BTMP
/*
 * Logs failed login attempts in _PATH_BTMP if that exists.
 * The most common login failure is to give password instead of username.
 * So the _PATH_BTMP file is checked for the correct permission, so that only
 * root can read it.
 */
శూన్య
రికార్డు_failed_login(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *username, స్థిరరాశి అక్షరం *hostname,
    స్థిరరాశి అక్షరం *ttyn)
{
	పూర్ణాంకం fd;
	నిర్మాణం utmp ut;
	నిర్మాణం logininfo li;
	socklen_t fromlen = పరిమాణం(li.hostaddr);
	time_t t;
	నిర్మాణం stat fst;

	ఒకవేళ (geteuid() != 0)
		తిరిగి;
	ఒకవేళ ((fd = open(మార్గం_BTMP, O_WRONLY | O_APPEND)) < 0) {
		debug("Unable to open the btmp file %s: %s", మార్గం_BTMP,
		    strerror(errno));
		తిరిగి;
	}
	ఒకవేళ (fstat(fd, &fst) < 0) {
		logit("%s: fstat of %s failed: %s", __func__, మార్గం_BTMP,
		    strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((fst.st_mode & (S_IXGRP | S_IRWXO)) || fst.st_uid != 0) {
		logit("Excess permission or bad ownership on file %s",
		    మార్గం_BTMP);
		వెళ్ళు బహిర్గతం;
	}

	/* Construct a logininfo and turn it into a utmp */
	memset(&li, 0, పరిమాణం(li));
	li.type = LTYPE_FAILED;
	li.pid = getpid();
	strlcpy(li.పంక్తి, "ssh:notty", పరిమాణం(li.పంక్తి));
	strlcpy(li.username, username, పరిమాణం(li.username));
	strlcpy(li.hostname, hostname, పరిమాణం(li.hostname));
	time(&t);
	li.tv_sec = t > 0 ? (గుర్తులేని దీర్ఘ)t : 0;
	ఒకవేళ (ssh_packet_connection_is_on_socket(ssh)) {
		(శూన్య)getpeername(ssh_packet_get_connection_లోపల(ssh),
		    &li.hostaddr.sa, &fromlen);
	}
	construct_utmp(&li, &ut);

	ఒకవేళ (atomicio(vwrite, fd, &ut, పరిమాణం(ut)) != పరిమాణం(ut)) {
		error("Failed to write to %s: %s", మార్గం_BTMP,
		    strerror(errno));
	}
బహిర్గతం:
	close(fd);
}
#అయితే_ముగింపు	/* USE_BTMP */
