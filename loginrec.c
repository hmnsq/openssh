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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/time.h>

#अन्तर्भाव <netinet/in.h>

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "loginrec.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "misc.h"

# include <util.h>

#यदि_परिभाषितम् USE_WTMPDB
# include <wtmpdb.h>
#यदि_अन्तः

/**
 ** prototypes for helper functions in this file
 **/

#यदि HAVE_UTMP_H
शून्य समुच्चयः_utmp_time(संरचना logininfo *li, संरचना utmp *ut);
शून्य construct_utmp(संरचना logininfo *li, संरचना utmp *ut);
#यदि_अन्तः

#यदि_परिभाषितम् HAVE_UTMPX_H
शून्य समुच्चयः_utmpx_time(संरचना logininfo *li, संरचना utmpx *ut);
शून्य construct_utmpx(संरचना logininfo *li, संरचना utmpx *ut);
#यदि_अन्तः

पूर्णाङ्क utmp_write_प्रविष्टिः(संरचना logininfo *li);
पूर्णाङ्क utmpx_write_प्रविष्टिः(संरचना logininfo *li);
पूर्णाङ्क wtmp_write_प्रविष्टिः(संरचना logininfo *li);
पूर्णाङ्क wtmpx_write_प्रविष्टिः(संरचना logininfo *li);
पूर्णाङ्क lastlog_write_प्रविष्टिः(संरचना logininfo *li);
पूर्णाङ्क syslogin_write_प्रविष्टिः(संरचना logininfo *li);
#यदि_परिभाषितम् USE_WTMPDB
पूर्णाङ्क wtmpdb_write_प्रविष्टिः(संरचना logininfo *li);
#यदि_अन्तः

पूर्णाङ्क getlast_प्रविष्टिः(संरचना logininfo *li);
पूर्णाङ्क lastlog_get_प्रविष्टिः(संरचना logininfo *li);
पूर्णाङ्क utmpx_get_प्रविष्टिः(संरचना logininfo *li);
पूर्णाङ्क wtmp_get_प्रविष्टिः(संरचना logininfo *li);
पूर्णाङ्क wtmpx_get_प्रविष्टिः(संरचना logininfo *li);

बाह्य संरचना sshbuf *loginmsg;

/* pick the shortest string */
#परिभाषय MIN_SIZEOF(s1,s2) (परिमाण(s1) < परिमाण(s2) ? परिमाण(s1) : परिमाण(s2))

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
पूर्णाङ्क
login_login(संरचना logininfo *li)
{
	li->type = LTYPE_LOGIN;
	प्रत्यागम (login_write(li));
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
पूर्णाङ्क
login_logout(संरचना logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	प्रत्यागम (login_write(li));
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
अचिह्नित पूर्णाङ्क
login_get_lastlog_time(ध्रुव uid_t uid)
{
	संरचना logininfo li;

	यदि (login_get_lastlog(&li, uid))
		प्रत्यागम (li.tv_sec);
	अन्यथा
		प्रत्यागम (0);
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
संरचना logininfo *
login_get_lastlog(संरचना logininfo *li, ध्रुव uid_t uid)
{
	संरचना passwd *pw;

	स्मृतिं_पूरय(li, '\0', परिमाण(*li));
	li->uid = uid;

	/*
	 * If we don't have a 'real' lastlog, we need the username to
	 * reliably search wtmp(x) for the last login (see
	 * wtmp_get_entry().)
	 */
	pw = getpwuid(uid);
	यदि (pw == रिक्त)
		fatal("%s: Cannot find account for uid %ld", __func__,
		    (दीर्घ)uid);

	यदि (strlcpy(li->username, pw->pw_name, परिमाण(li->username)) >=
	    परिमाण(li->username)) {
		error("%s: username too long (%lu > max %lu)", __func__,
		    (अचिह्नित दीर्घ)वाक्यदैर्घ्यम्(pw->pw_name),
		    (अचिह्नित दीर्घ)परिमाण(li->username) - 1);
		प्रत्यागम रिक्त;
	}

	यदि (getlast_प्रविष्टिः(li))
		प्रत्यागम (li);
	अन्यथा
		प्रत्यागम (रिक्त);
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
संरचना
logininfo *login_alloc_प्रविष्टिः(pid_t pid, ध्रुव वर्ण *username,
    ध्रुव वर्ण *hostname, ध्रुव वर्ण *पङ्क्तिः)
{
	संरचना logininfo *newli;

	newli = xmalloc(परिमाण(*newli));
	login_init_प्रविष्टिः(newli, pid, username, hostname, पङ्क्तिः);
	प्रत्यागम (newli);
}


/* login_free_entry(struct logininfo *)    - free struct memory */
शून्य
login_free_प्रविष्टिः(संरचना logininfo *li)
{
	मुक्त(li);
}


/* login_init_entry(struct logininfo *, int, char*, char*, char*)
 *                                        - initialise a struct logininfo
 *
 * Populates a new struct logininfo, a data structure meant to carry
 * the information required to portably record login info.
 *
 * Returns: 1
 */
पूर्णाङ्क
login_init_प्रविष्टिः(संरचना logininfo *li, pid_t pid, ध्रुव वर्ण *username,
    ध्रुव वर्ण *hostname, ध्रुव वर्ण *पङ्क्तिः)
{
	संरचना passwd *pw;

	स्मृतिं_पूरय(li, 0, परिमाण(*li));

	li->pid = pid;

	/* set the line information */
	यदि (पङ्क्तिः)
		पङ्क्तिः_fullname(li->पङ्क्तिः, पङ्क्तिः, परिमाण(li->पङ्क्तिः));

	यदि (username) {
		strlcpy(li->username, username, परिमाण(li->username));
		pw = getpwnam(li->username);
		यदि (pw == रिक्त) {
			fatal("%s: Cannot find user \"%s\"", __func__,
			    li->username);
		}
		li->uid = pw->pw_uid;
	}

	यदि (hostname)
		strlcpy(li->hostname, hostname, परिमाण(li->hostname));

	प्रत्यागम (1);
}

/*
 * login_set_current_time(struct logininfo *)    - set the current time
 *
 * Set the current time in a logininfo structure. This function is
 * meant to eliminate the need to deal with system dependencies for
 * time handling.
 */
शून्य
login_समुच्चयः_current_time(संरचना logininfo *li)
{
	संरचना timeval tv;

	gettimeofday(&tv, रिक्त);

	li->tv_sec = tv.tv_sec;
	li->tv_usec = tv.tv_usec;
}

/* copy a sockaddr_* into our logininfo */
शून्य
login_समुच्चयः_addr(संरचना logininfo *li, ध्रुव संरचना sockaddr *sa,
    ध्रुव अचिह्नित पूर्णाङ्क sa_आकार)
{
	अचिह्नित पूर्णाङ्क bufsize = sa_आकार;

	/* make sure we don't overrun our union */
	यदि (परिमाण(li->hostaddr) < sa_आकार)
		bufsize = परिमाण(li->hostaddr);

	स्मृतिं_प्रतिलिख(&li->hostaddr.sa, sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/
पूर्णाङ्क
login_write(संरचना logininfo *li)
{
#यदि_अपरिभाषितम् HAVE_CYGWIN
	यदि (geteuid() != 0) {
		logit("Attempt to write login records by non-root user (aborting)");
		प्रत्यागम (1);
	}
#यदि_अन्तः

	/* set the timestamp */
	login_समुच्चयः_current_time(li);
#यदि_परिभाषितम् USE_LOGIN
	syslogin_write_प्रविष्टिः(li);
#यदि_अन्तः
#यदि_परिभाषितम् USE_LASTLOG
	यदि (li->type == LTYPE_LOGIN)
		lastlog_write_प्रविष्टिः(li);
#यदि_अन्तः
#यदि_परिभाषितम् USE_UTMP
	utmp_write_प्रविष्टिः(li);
#यदि_अन्तः
#यदि_परिभाषितम् USE_WTMP
	wtmp_write_प्रविष्टिः(li);
#यदि_अन्तः
#यदि_परिभाषितम् USE_UTMPX
	utmpx_write_प्रविष्टिः(li);
#यदि_अन्तः
#यदि_परिभाषितम् USE_WTMPX
	wtmpx_write_प्रविष्टिः(li);
#यदि_अन्तः
#यदि_परिभाषितम् USE_WTMPDB
	wtmpdb_write_प्रविष्टिः(li);
#यदि_अन्तः
#यदि_परिभाषितम् CUSTOM_SYS_AUTH_लेखः_LOGIN
	यदि (li->type == LTYPE_LOGIN &&
	    !sys_auth_लेखः_login(li->username,li->hostname,li->पङ्क्तिः,
	    loginmsg))
		logit("Writing login record failed for %s", li->username);
#यदि_अन्तः
#यदि_परिभाषितम् SSH_AUDIT_EVENTS
	यदि (li->type == LTYPE_LOGIN)
		audit_session_open(li);
	अन्यथा यदि (li->type == LTYPE_LOGOUT)
		audit_session_close(li);
#यदि_अन्तः
	प्रत्यागम (0);
}

#यदि_परिभाषितम् LOGIN_NEEDS_UTMPX
पूर्णाङ्क
login_utmp_only(संरचना logininfo *li)
{
	li->type = LTYPE_LOGIN;
	login_समुच्चयः_current_time(li);
# ifdef USE_UTMP
	utmp_write_प्रविष्टिः(li);
# endif
# ifdef USE_WTMP
	wtmp_write_प्रविष्टिः(li);
# endif
# ifdef USE_UTMPX
	utmpx_write_प्रविष्टिः(li);
# endif
# ifdef USE_WTMPX
	wtmpx_write_प्रविष्टिः(li);
# endif
	प्रत्यागम (0);
}
#यदि_अन्तः

/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
पूर्णाङ्क
getlast_प्रविष्टिः(संरचना logininfo *li)
{
#यदि_परिभाषितम् USE_LASTLOG
	प्रत्यागम(lastlog_get_प्रविष्टिः(li));
#अन्यथा /* !USE_LASTLOG */
#यदि defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
	प्रत्यागम (utmpx_get_प्रविष्टिः(li));
#यदि_अन्तः

#यदि defined(DISABLE_LASTLOG)
	/* On some systems we shouldn't even try to obtain last login
	 * time, e.g. AIX */
	प्रत्यागम (0);
# elif defined(USE_WTMP) && \
    (defined(HAVE_TIME_अन्तर्_UTMP) || defined(HAVE_TV_अन्तर्_UTMP))
	/* retrieve last login time from utmp */
	प्रत्यागम (wtmp_get_प्रविष्टिः(li));
# elif defined(USE_WTMPX) && \
    (defined(HAVE_TIME_अन्तर्_UTMPX) || defined(HAVE_TV_अन्तर्_UTMPX))
	/* If wtmp isn't available, try wtmpx */
	प्रत्यागम (wtmpx_get_प्रविष्टिः(li));
# अन्यथा
	/* Give up: No means of retrieving last login time */
	प्रत्यागम (0);
# endif /* DISABLE_LASTLOG */
#यदि_अन्तः /* USE_LASTLOG */
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
वर्ण *
पङ्क्तिः_fullname(वर्ण *dst, ध्रुव वर्ण *src, u_int dstsize)
{
	स्मृतिं_पूरय(dst, '\0', dstsize);
	यदि ((वाक्ये_तुलय(src, "/dev/", 5) == 0) || (dstsize < (वाक्यदैर्घ्यम्(src) + 5)))
		strlcpy(dst, src, dstsize);
	अन्यथा {
		strlcpy(dst, "/dev/", dstsize);
		strlcat(dst, src, dstsize);
	}
	प्रत्यागम (dst);
}

/* line_stripname(): strip the leading '/dev' if it exists, return dst */
वर्ण *
पङ्क्तिः_stripname(वर्ण *dst, ध्रुव वर्ण *src, पूर्णाङ्क dstsize)
{
	स्मृतिं_पूरय(dst, '\0', dstsize);
	यदि (वाक्ये_तुलय(src, "/dev/", 5) == 0)
		strlcpy(dst, src + 5, dstsize);
	अन्यथा
		strlcpy(dst, src, dstsize);
	प्रत्यागम (dst);
}

/*
 * line_abbrevname(): Return the abbreviated (usually four-character)
 * form of the line (Just use the last <dstsize> characters of the
 * full name.)
 *
 * NOTE: use strncpy because we do NOT necessarily want zero
 * termination
 */
वर्ण *
पङ्क्तिः_abbrevname(वर्ण *dst, ध्रुव वर्ण *src, पूर्णाङ्क dstsize)
{
	आकार_t len;

	स्मृतिं_पूरय(dst, '\0', dstsize);

	यदि (वाक्यं_तुलय(src, "ssh:notty") == 0)
		प्रत्यागम dst;

	/* Always skip prefix if present */
	यदि (वाक्ये_तुलय(src, "/dev/", 5) == 0)
		src += 5;

#यदि_परिभाषितम् WITH_ABBREV_NO_TTY
	यदि (वाक्ये_तुलय(src, "tty", 3) == 0)
		src += 3;
#यदि_अन्तः

	len = वाक्यदैर्घ्यम्(src);

	यदि (len > 0) {
		यदि (((पूर्णाङ्क)len - dstsize) > 0)
			src +=  ((पूर्णाङ्क)len - dstsize);

		/* note: _don't_ change this to strlcpy */
		strncpy(dst, src, (आकार_t)dstsize);
	}

	प्रत्यागम (dst);
}

/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#यदि defined(USE_BTMP) || defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
शून्य
समुच्चयः_utmp_time(संरचना logininfo *li, संरचना utmp *ut)
{
# यदि defined(HAVE_TV_अन्तर्_UTMP)
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_अन्तर्_UTMP)
	ut->ut_time = li->tv_sec;
# endif
}

शून्य
construct_utmp(संरचना logininfo *li,
		    संरचना utmp *ut)
{
# ifdef HAVE_ADDR_V6_अन्तर्_UTMP
	संरचना sockaddr_in6 *sa6;
# endif

	स्मृतिं_पूरय(ut, '\0', परिमाण(*ut));

	/* First fill out fields used for both logins and logouts */

# ifdef HAVE_ID_अन्तर्_UTMP
	पङ्क्तिः_abbrevname(ut->ut_id, li->पङ्क्तिः, परिमाण(ut->ut_id));
# endif

# ifdef HAVE_TYPE_अन्तर्_UTMP
	/* This is done here to keep utmp constants out of struct logininfo */
	विकल्प (li->type) {
	पक्ष LTYPE_FAILED:
		ut->ut_type = LOGIN_PROCESS;
		भङ्ग;
	पक्ष LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		भङ्ग;
	पक्ष LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		भङ्ग;
	}
# endif
	समुच्चयः_utmp_time(li, ut);

	पङ्क्तिः_stripname(ut->ut_पङ्क्तिः, li->पङ्क्तिः, परिमाण(ut->ut_पङ्क्तिः));

# ifdef HAVE_PID_अन्तर्_UTMP
	ut->ut_pid = li->pid;
# endif

	/* If we're logging out, leave all other fields blank */
	यदि (li->type == LTYPE_LOGOUT)
		प्रत्यागम;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

	/* Use strncpy because we don't necessarily want null termination */
	strncpy(ut->ut_name, li->username,
	    MIN_SIZEOF(ut->ut_name, li->username));
# ifdef HAVE_HOST_अन्तर्_UTMP
	strncpy(ut->ut_host, li->hostname,
	    MIN_SIZEOF(ut->ut_host, li->hostname));
# endif
# ifdef HAVE_ADDR_अन्तर्_UTMP
	/* this is just a 32-bit IP address */
	यदि (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_अन्तर्.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_अन्तर्_UTMP
	/* this is just a 128-bit IPv6 address */
	यदि (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((संरचना sockaddr_in6 *)&li->hostaddr.sa);
		स्मृतिं_प्रतिलिख(ut->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		यदि (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			ut->ut_addr_v6[0] = ut->ut_addr_v6[3];
			ut->ut_addr_v6[1] = 0;
			ut->ut_addr_v6[2] = 0;
			ut->ut_addr_v6[3] = 0;
		}
	}
# endif
}
#यदि_अन्तः /* USE_BTMP || USE_UTMP || USE_WTMP || USE_LOGIN */

/**
 ** utmpx utility functions
 **
 ** These functions manipulate struct utmpx, accounting for system
 ** variations.
 **/

#यदि defined(USE_UTMPX) || defined (USE_WTMPX)
/* build the utmpx structure */
शून्य
समुच्चयः_utmpx_time(संरचना logininfo *li, संरचना utmpx *utx)
{
# यदि defined(HAVE_TV_अन्तर्_UTMPX)
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_अन्तर्_UTMPX)
	utx->ut_time = li->tv_sec;
# endif
}

शून्य
construct_utmpx(संरचना logininfo *li, संरचना utmpx *utx)
{
# ifdef HAVE_ADDR_V6_अन्तर्_UTMPX
	संरचना sockaddr_in6 *sa6;
#  endif
	स्मृतिं_पूरय(utx, '\0', परिमाण(*utx));

# ifdef HAVE_ID_अन्तर्_UTMPX
	पङ्क्तिः_abbrevname(utx->ut_id, li->पङ्क्तिः, परिमाण(utx->ut_id));
# endif

	/* this is done here to keep utmp constants out of loginrec.h */
	विकल्प (li->type) {
	पक्ष LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		भङ्ग;
	पक्ष LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		भङ्ग;
	}
	पङ्क्तिः_stripname(utx->ut_पङ्क्तिः, li->पङ्क्तिः, परिमाण(utx->ut_पङ्क्तिः));
	समुच्चयः_utmpx_time(li, utx);
	utx->ut_pid = li->pid;

	/* strncpy(): Don't necessarily want null termination */
	strncpy(utx->ut_user, li->username,
	    MIN_SIZEOF(utx->ut_user, li->username));

	यदि (li->type == LTYPE_LOGOUT)
		प्रत्यागम;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

# ifdef HAVE_HOST_अन्तर्_UTMPX
	strncpy(utx->ut_host, li->hostname,
	    MIN_SIZEOF(utx->ut_host, li->hostname));
# endif
# ifdef HAVE_SS_अन्तर्_UTMPX
	utx->ut_ss = li->hostaddr.sa_storage;
# endif
# ifdef HAVE_ADDR_अन्तर्_UTMPX
	/* this is just a 32-bit IP address */
	यदि (li->hostaddr.sa.sa_family == AF_INET)
		utx->ut_addr = li->hostaddr.sa_अन्तर्.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_अन्तर्_UTMPX
	/* this is just a 128-bit IPv6 address */
	यदि (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((संरचना sockaddr_in6 *)&li->hostaddr.sa);
		स्मृतिं_प्रतिलिख(utx->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		यदि (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			utx->ut_addr_v6[0] = utx->ut_addr_v6[3];
			utx->ut_addr_v6[1] = 0;
			utx->ut_addr_v6[2] = 0;
			utx->ut_addr_v6[3] = 0;
		}
	}
# endif
# ifdef HAVE_SYSLEN_अन्तर्_UTMPX
	/* ut_syslen is the length of the utx_host string */
	utx->ut_syslen = MINIMUM(वाक्यदैर्घ्यम्(li->hostname), परिमाण(utx->ut_host));
# endif
}
#यदि_अन्तः /* USE_UTMPX || USE_WTMPX */

/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */
#यदि_परिभाषितम् USE_UTMP

/* if we can, use pututline() etc. */
# यदि !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
	defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
# endif


/* write a utmp entry with the system's help (pututline() and pals) */
# ifdef UTMP_USE_LIBRARY
स्थिर पूर्णाङ्क
utmp_write_library(संरचना logininfo *li, संरचना utmp *ut)
{
	setutent();
	pututline(ut);
#  ifdef HAVE_ENDUTENT
	endutent();
#  endif
	प्रत्यागम (1);
}
# अन्यथा /* UTMP_USE_LIBRARY */

/*
 * Write a utmp entry direct to the file
 * This is a slightly modification of code in OpenBSD's login.c
 */
स्थिर पूर्णाङ्क
utmp_write_प्रत्यक्षम्(संरचना logininfo *li, संरचना utmp *ut)
{
	संरचना utmp old_ut;
	पञ्जिका पूर्णाङ्क fd;
	पूर्णाङ्क tty;

	/* FIXME: (ATL) ttyslot() needs local implementation */

#यदि defined(HAVE_GETTTYENT)
	संरचना ttyent *ty;

	tty=0;
	setttyent();
	यावत् (रिक्त != (ty = getttyent())) {
		tty++;
		यदि (!वाक्ये_तुलय(ty->ty_name, ut->ut_पङ्क्तिः, परिमाण(ut->ut_पङ्क्तिः)))
			भङ्ग;
	}
	endttyent();

	यदि (रिक्त == ty) {
		logit_f("tty not found");
		प्रत्यागम (0);
	}
#अन्यथा /* FIXME */

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

#यदि_अन्तः /* HAVE_GETTTYENT */

	यदि (tty > 0 && (fd = उद्घाटय(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		off_t pos, ret;

		pos = (off_t)tty * परिमाण(संरचना utmp);
		यदि ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			प्रत्यागम (0);
		}
		यदि (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			प्रत्यागम (0);
		}
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		यदि (atomicio(पठ, fd, &old_ut, परिमाण(old_ut)) == परिमाण(old_ut) &&
		    (ut->ut_host[0] == '\0') && (old_ut.ut_host[0] != '\0') &&
		    (वाक्ये_तुलय(old_ut.ut_पङ्क्तिः, ut->ut_पङ्क्तिः, परिमाण(ut->ut_पङ्क्तिः)) == 0) &&
		    (वाक्ये_तुलय(old_ut.ut_name, ut->ut_name, परिमाण(ut->ut_name)) == 0))
			स्मृतिं_प्रतिलिख(ut->ut_host, old_ut.ut_host, परिमाण(ut->ut_host));

		यदि ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			प्रत्यागम (0);
		}
		यदि (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			प्रत्यागम (0);
		}
		यदि (atomicio(vwrite, fd, ut, परिमाण(*ut)) != परिमाण(*ut)) {
			logit("%s: error writing %s: %s", __func__,
			    UTMP_FILE, strerror(errno));
			close(fd);
			प्रत्यागम (0);
		}

		close(fd);
		प्रत्यागम (1);
	} अन्यथा {
		प्रत्यागम (0);
	}
}
# endif /* UTMP_USE_LIBRARY */

स्थिर पूर्णाङ्क
utmp_perform_login(संरचना logininfo *li)
{
	संरचना utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	यदि (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		प्रत्यागम (0);
	}
# अन्यथा
	यदि (!utmp_write_प्रत्यक्षम्(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		प्रत्यागम (0);
	}
# endif
	प्रत्यागम (1);
}


स्थिर पूर्णाङ्क
utmp_perform_logout(संरचना logininfo *li)
{
	संरचना utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	यदि (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		प्रत्यागम (0);
	}
# अन्यथा
	यदि (!utmp_write_प्रत्यक्षम्(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		प्रत्यागम (0);
	}
# endif
	प्रत्यागम (1);
}


पूर्णाङ्क
utmp_write_प्रविष्टिः(संरचना logininfo *li)
{
	विकल्प(li->type) {
	पक्ष LTYPE_LOGIN:
		प्रत्यागम (utmp_perform_login(li));

	पक्ष LTYPE_LOGOUT:
		प्रत्यागम (utmp_perform_logout(li));

	स्वभाव:
		logit_f("invalid type field");
		प्रत्यागम (0);
	}
}
#यदि_अन्तः /* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#यदि_परिभाषितम् USE_UTMPX

/* if we have the wherewithal, use pututxline etc. */
# यदि !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) && \
	defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
# endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
# ifdef UTMPX_USE_LIBRARY
स्थिर पूर्णाङ्क
utmpx_write_library(संरचना logininfo *li, संरचना utmpx *utx)
{
	setutxent();
	pututxline(utx);

#  ifdef HAVE_ENDUTXENT
	endutxent();
#  endif
	प्रत्यागम (1);
}

# अन्यथा /* UTMPX_USE_LIBRARY */

/* write a utmp entry direct to the file */
स्थिर पूर्णाङ्क
utmpx_write_प्रत्यक्षम्(संरचना logininfo *li, संरचना utmpx *utx)
{
	logit_f("not implemented!");
	प्रत्यागम (0);
}
# endif /* UTMPX_USE_LIBRARY */

स्थिर पूर्णाङ्क
utmpx_perform_login(संरचना logininfo *li)
{
	संरचना utmpx utx;

	construct_utmpx(li, &utx);
# ifdef UTMPX_USE_LIBRARY
	यदि (!utmpx_write_library(li, &utx)) {
		logit_f("utmp_write_library() failed");
		प्रत्यागम (0);
	}
# अन्यथा
	यदि (!utmpx_write_प्रत्यक्षम्(li, &utx)) {
		logit_f("utmp_write_direct() failed");
		प्रत्यागम (0);
	}
# endif
	प्रत्यागम (1);
}


स्थिर पूर्णाङ्क
utmpx_perform_logout(संरचना logininfo *li)
{
	संरचना utmpx utx;

	construct_utmpx(li, &utx);
# ifdef HAVE_ID_अन्तर्_UTMPX
	पङ्क्तिः_abbrevname(utx.ut_id, li->पङ्क्तिः, परिमाण(utx.ut_id));
# endif
# ifdef HAVE_TYPE_अन्तर्_UTMPX
	utx.ut_type = DEAD_PROCESS;
# endif

# ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
# अन्यथा
	utmpx_write_प्रत्यक्षम्(li, &utx);
# endif
	प्रत्यागम (1);
}

पूर्णाङ्क
utmpx_write_प्रविष्टिः(संरचना logininfo *li)
{
	विकल्प(li->type) {
	पक्ष LTYPE_LOGIN:
		प्रत्यागम (utmpx_perform_login(li));
	पक्ष LTYPE_LOGOUT:
		प्रत्यागम (utmpx_perform_logout(li));
	स्वभाव:
		logit_f("invalid type field");
		प्रत्यागम (0);
	}
}
#यदि_अन्तः /* USE_UTMPX */


/**
 ** Low-level wtmp functions
 **/

#यदि_परिभाषितम् USE_WTMP

/*
 * Write a wtmp entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
स्थिर पूर्णाङ्क
wtmp_write(संरचना logininfo *li, संरचना utmp *ut)
{
	संरचना stat buf;
	पूर्णाङ्क fd, ret = 1;

	यदि ((fd = उद्घाटय(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem writing %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		प्रत्यागम (0);
	}
	यदि (fstat(fd, &buf) == 0)
		यदि (atomicio(vwrite, fd, ut, परिमाण(*ut)) != परिमाण(*ut)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMP_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);
	प्रत्यागम (ret);
}

स्थिर पूर्णाङ्क
wtmp_perform_login(संरचना logininfo *li)
{
	संरचना utmp ut;

	construct_utmp(li, &ut);
	प्रत्यागम (wtmp_write(li, &ut));
}


स्थिर पूर्णाङ्क
wtmp_perform_logout(संरचना logininfo *li)
{
	संरचना utmp ut;

	construct_utmp(li, &ut);
	प्रत्यागम (wtmp_write(li, &ut));
}


पूर्णाङ्क
wtmp_write_प्रविष्टिः(संरचना logininfo *li)
{
	विकल्प(li->type) {
	पक्ष LTYPE_LOGIN:
		प्रत्यागम (wtmp_perform_login(li));
	पक्ष LTYPE_LOGOUT:
		प्रत्यागम (wtmp_perform_logout(li));
	स्वभाव:
		logit_f("invalid type field");
		प्रत्यागम (0);
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
स्थिर पूर्णाङ्क
wtmp_islogin(संरचना logininfo *li, संरचना utmp *ut)
{
	यदि (वाक्ये_तुलय(li->username, ut->ut_name,
	    MIN_SIZEOF(li->username, ut->ut_name)) == 0) {
# ifdef HAVE_TYPE_अन्तर्_UTMP
		यदि (ut->ut_type & USER_PROCESS)
			प्रत्यागम (1);
# अन्यथा
		प्रत्यागम (1);
# endif
	}
	प्रत्यागम (0);
}

पूर्णाङ्क
wtmp_get_प्रविष्टिः(संरचना logininfo *li)
{
	संरचना stat st;
	संरचना utmp ut;
	पूर्णाङ्क fd, प्राप्तम् = 0;

	/* Clear the time entries in our logininfo */
	li->tv_sec = li->tv_usec = 0;

	यदि ((fd = उद्घाटय(WTMP_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		प्रत्यागम (0);
	}
	यदि (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		close(fd);
		प्रत्यागम (0);
	}

	/* Seek to the start of the last struct utmp */
	यदि (lseek(fd, -(off_t)परिमाण(संरचना utmp), SEEK_END) == -1) {
		/* Looks like we've got a fresh wtmp file */
		close(fd);
		प्रत्यागम (0);
	}

	यावत् (!प्राप्तम्) {
		यदि (atomicio(पठ, fd, &ut, परिमाण(ut)) != परिमाण(ut)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMP_FILE, strerror(errno));
			close (fd);
			प्रत्यागम (0);
		}
		यदि (wtmp_islogin(li, &ut) ) {
			प्राप्तम् = 1;
			/*
			 * We've already checked for a time in struct
			 * utmp, in login_getlast()
			 */
# ifdef HAVE_TIME_अन्तर्_UTMP
			li->tv_sec = ut.ut_time;
# अन्यथा
#  यदि HAVE_TV_अन्तर्_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
# endif
			पङ्क्तिः_fullname(li->पङ्क्तिः, ut.ut_पङ्क्तिः,
			    MIN_SIZEOF(li->पङ्क्तिः, ut.ut_पङ्क्तिः));
# ifdef HAVE_HOST_अन्तर्_UTMP
			strlcpy(li->hostname, ut.ut_host,
			    MIN_SIZEOF(li->hostname, ut.ut_host));
# endif
			अनुवर्त;
		}
		/* Seek back 2 x struct utmp */
		यदि (lseek(fd, -(off_t)(2 * परिमाण(संरचना utmp)), SEEK_CUR) == -1) {
			/* We've found the start of the file, so quit */
			close(fd);
			प्रत्यागम (0);
		}
	}

	/* We found an entry. Tidy up and return */
	close(fd);
	प्रत्यागम (1);
}
# endif /* USE_WTMP */


/**
 ** Low-level wtmpx functions
 **/

#यदि_परिभाषितम् USE_WTMPX
/*
 * Write a wtmpx entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
स्थिर पूर्णाङ्क
wtmpx_write(संरचना logininfo *li, संरचना utmpx *utx)
{
#यदि_अपरिभाषितम् HAVE_UPDWTMPX
	संरचना stat buf;
	पूर्णाङ्क fd, ret = 1;

	यदि ((fd = उद्घाटय(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		प्रत्यागम (0);
	}

	यदि (fstat(fd, &buf) == 0)
		यदि (atomicio(vwrite, fd, utx, परिमाण(*utx)) != परिमाण(*utx)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);

	प्रत्यागम (ret);
#अन्यथा
	updwtmpx(WTMPX_FILE, utx);
	प्रत्यागम (1);
#यदि_अन्तः
}


स्थिर पूर्णाङ्क
wtmpx_perform_login(संरचना logininfo *li)
{
	संरचना utmpx utx;

	construct_utmpx(li, &utx);
	प्रत्यागम (wtmpx_write(li, &utx));
}


स्थिर पूर्णाङ्क
wtmpx_perform_logout(संरचना logininfo *li)
{
	संरचना utmpx utx;

	construct_utmpx(li, &utx);
	प्रत्यागम (wtmpx_write(li, &utx));
}


पूर्णाङ्क
wtmpx_write_प्रविष्टिः(संरचना logininfo *li)
{
	विकल्प(li->type) {
	पक्ष LTYPE_LOGIN:
		प्रत्यागम (wtmpx_perform_login(li));
	पक्ष LTYPE_LOGOUT:
		प्रत्यागम (wtmpx_perform_logout(li));
	स्वभाव:
		logit_f("invalid type field");
		प्रत्यागम (0);
	}
}

/* Please see the notes above wtmp_islogin() for information about the
   next two functions */

/* Return true if this wtmpx entry indicates a login */
स्थिर पूर्णाङ्क
wtmpx_islogin(संरचना logininfo *li, संरचना utmpx *utx)
{
	यदि (वाक्ये_तुलय(li->username, utx->ut_user,
	    MIN_SIZEOF(li->username, utx->ut_user)) == 0 ) {
# ifdef HAVE_TYPE_अन्तर्_UTMPX
		यदि (utx->ut_type == USER_PROCESS)
			प्रत्यागम (1);
# अन्यथा
		प्रत्यागम (1);
# endif
	}
	प्रत्यागम (0);
}


पूर्णाङ्क
wtmpx_get_प्रविष्टिः(संरचना logininfo *li)
{
	संरचना stat st;
	संरचना utmpx utx;
	पूर्णाङ्क fd, प्राप्तम्=0;

	/* Clear the time entries */
	li->tv_sec = li->tv_usec = 0;

	यदि ((fd = उद्घाटय(WTMPX_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		प्रत्यागम (0);
	}
	यदि (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		close(fd);
		प्रत्यागम (0);
	}

	/* Seek to the start of the last struct utmpx */
	यदि (lseek(fd, -(off_t)परिमाण(संरचना utmpx), SEEK_END) == -1 ) {
		/* probably a newly rotated wtmpx file */
		close(fd);
		प्रत्यागम (0);
	}

	यावत् (!प्राप्तम्) {
		यदि (atomicio(पठ, fd, &utx, परिमाण(utx)) != परिमाण(utx)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			close (fd);
			प्रत्यागम (0);
		}
		/*
		 * Logouts are recorded as a blank username on a particular
		 * line. So, we just need to find the username in struct utmpx
		 */
		यदि (wtmpx_islogin(li, &utx)) {
			प्राप्तम् = 1;
# यदि defined(HAVE_TV_अन्तर्_UTMPX)
			li->tv_sec = utx.ut_tv.tv_sec;
# elif defined(HAVE_TIME_अन्तर्_UTMPX)
			li->tv_sec = utx.ut_time;
# endif
			पङ्क्तिः_fullname(li->पङ्क्तिः, utx.ut_पङ्क्तिः, परिमाण(li->पङ्क्तिः));
# यदि defined(HAVE_HOST_अन्तर्_UTMPX)
			strlcpy(li->hostname, utx.ut_host,
			    MIN_SIZEOF(li->hostname, utx.ut_host));
# endif
			अनुवर्त;
		}
		यदि (lseek(fd, -(off_t)(2 * परिमाण(संरचना utmpx)), SEEK_CUR) == -1) {
			close(fd);
			प्रत्यागम (0);
		}
	}

	close(fd);
	प्रत्यागम (1);
}
#यदि_अन्तः /* USE_WTMPX */

#यदि_परिभाषितम् USE_WTMPDB
स्थिर पूर्णाङ्क
wtmpdb_perform_login(संरचना logininfo *li)
{
	uint64_t login_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	    li->tv_usec;
	ध्रुव वर्ण *tty;

	यदि (वाक्ये_तुलय(li->पङ्क्तिः, "/dev/", 5) == 0)
		tty = &(li->पङ्क्तिः[5]);
	अन्यथा
		tty = li->पङ्क्तिः;

	li->wtmpdb_id = wtmpdb_login(रिक्त, USER_PROCESS, li->username,
	    login_time, tty, li->hostname, 0, 0);

	यदि (li->wtmpdb_id < 0)
		प्रत्यागम (0);

	प्रत्यागम (1);
}

स्थिर पूर्णाङ्क
wtmpdb_perform_logout(संरचना logininfo *li)
{
	uint64_t logout_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	   li->tv_usec;

	यदि (li->wtmpdb_id == 0) {
		ध्रुव वर्ण *tty;

		यदि (वाक्ये_तुलय(li->पङ्क्तिः, "/dev/", 5) == 0)
			tty = &(li->पङ्क्तिः[5]);
		अन्यथा
			tty = li->पङ्क्तिः;

		li->wtmpdb_id = wtmpdb_get_id(रिक्त, tty, रिक्त);
	}
	wtmpdb_logout(रिक्त, li->wtmpdb_id, logout_time, रिक्त);

	प्रत्यागम (1);
}

पूर्णाङ्क
wtmpdb_write_प्रविष्टिः(संरचना logininfo *li)
{
	विकल्प(li->type) {
	पक्ष LTYPE_LOGIN:
		प्रत्यागम (wtmpdb_perform_login(li));
	पक्ष LTYPE_LOGOUT:
		प्रत्यागम (wtmpdb_perform_logout(li));
	स्वभाव:
		logit_f("invalid type field");
		प्रत्यागम (0);
	}
}
#यदि_अन्तः

/**
 ** Low-level libutil login() functions
 **/

#यदि_परिभाषितम् USE_LOGIN
स्थिर पूर्णाङ्क
syslogin_perform_login(संरचना logininfo *li)
{
	संरचना utmp *ut;

	ut = xmalloc(परिमाण(*ut));
	construct_utmp(li, ut);
	login(ut);
	मुक्त(ut);

	प्रत्यागम (1);
}

स्थिर पूर्णाङ्क
syslogin_perform_logout(संरचना logininfo *li)
{
# ifdef HAVE_LOGOUT
	वर्ण पङ्क्तिः[UT_LINESIZE];

	(शून्य)पङ्क्तिः_stripname(पङ्क्तिः, li->पङ्क्तिः, परिमाण(पङ्क्तिः));

	यदि (!logout(पङ्क्तिः))
		logit_f("logout() returned an error");
#  ifdef HAVE_LOGWTMP
	अन्यथा
		logwtmp(पङ्क्तिः, "", "");
#  endif
	/* FIXME: (ATL - if the need arises) What to do if we have
	 * login, but no logout?  what if logout but no logwtmp? All
	 * routines are in libutil so they should all be there,
	 * but... */
# endif
	प्रत्यागम (1);
}

पूर्णाङ्क
syslogin_write_प्रविष्टिः(संरचना logininfo *li)
{
	विकल्प (li->type) {
	पक्ष LTYPE_LOGIN:
		प्रत्यागम (syslogin_perform_login(li));
	पक्ष LTYPE_LOGOUT:
		प्रत्यागम (syslogin_perform_logout(li));
	स्वभाव:
		logit_f("Invalid type field");
		प्रत्यागम (0);
	}
}
#यदि_अन्तः /* USE_LOGIN */

/* end of file log-syslogin.c */

/**
 ** Low-level lastlog functions
 **/

#यदि_परिभाषितम् USE_LASTLOG

#यदि !defined(LASTLOG_WRITE_PUTUTXLINE) || !defined(HAVE_GETLASTLOGXBYNAME)
/* open the file (using filemode) and seek to the login entry */
स्थिर पूर्णाङ्क
lastlog_openseek(संरचना logininfo *li, पूर्णाङ्क *fd, पूर्णाङ्क filemode)
{
	off_t विस्थापनम्;
	वर्ण lastlog_file[1024];
	संरचना stat st;

	यदि (stat(LASTLOG_FILE, &st) != 0) {
		logit("%s: Couldn't stat %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		प्रत्यागम (0);
	}
	यदि (S_ISDIR(st.st_mode)) {
		snprintf(lastlog_file, परिमाण(lastlog_file), "%s/%s",
		    LASTLOG_FILE, li->username);
	} अन्यथा यदि (S_ISREG(st.st_mode)) {
		strlcpy(lastlog_file, LASTLOG_FILE, परिमाण(lastlog_file));
	} अन्यथा {
		logit("%s: %.100s is not a file or directory!", __func__,
		    LASTLOG_FILE);
		प्रत्यागम (0);
	}

	*fd = उद्घाटय(lastlog_file, filemode, 0600);
	यदि (*fd < 0) {
		debug("%s: Couldn't open %s: %s", __func__,
		    lastlog_file, strerror(errno));
		प्रत्यागम (0);
	}

	यदि (S_ISREG(st.st_mode)) {
		/* find this uid's offset in the lastlog file */
		विस्थापनम् = (off_t) ((u_long)li->uid * परिमाण(संरचना lastlog));

		यदि (lseek(*fd, विस्थापनम्, SEEK_SET) != विस्थापनम्) {
			logit("%s: %s->lseek(): %s", __func__,
			    lastlog_file, strerror(errno));
			close(*fd);
			प्रत्यागम (0);
		}
	}

	प्रत्यागम (1);
}
#यदि_अन्तः /* !LASTLOG_WRITE_PUTUTXLINE || !HAVE_GETLASTLOGXBYNAME */

#यदि_परिभाषितम् LASTLOG_WRITE_PUTUTXLINE
पूर्णाङ्क
lastlog_write_प्रविष्टिः(संरचना logininfo *li)
{
	विकल्प(li->type) {
	पक्ष LTYPE_LOGIN:
		प्रत्यागम 1; /* lastlog written by pututxline */
	स्वभाव:
		logit("lastlog_write_entry: Invalid type field");
		प्रत्यागम 0;
	}
}
#अन्यथा /* LASTLOG_WRITE_PUTUTXLINE */
पूर्णाङ्क
lastlog_write_प्रविष्टिः(संरचना logininfo *li)
{
	संरचना lastlog चरमः;
	पूर्णाङ्क fd;

	विकल्प(li->type) {
	पक्ष LTYPE_LOGIN:
		/* create our struct lastlog */
		स्मृतिं_पूरय(&चरमः, '\0', परिमाण(चरमः));
		पङ्क्तिः_stripname(चरमः.ll_पङ्क्तिः, li->पङ्क्तिः, परिमाण(चरमः.ll_पङ्क्तिः));
		strlcpy(चरमः.ll_host, li->hostname,
		    MIN_SIZEOF(चरमः.ll_host, li->hostname));
		चरमः.ll_time = li->tv_sec;

		यदि (!lastlog_openseek(li, &fd, O_RDWR|O_CREAT))
			प्रत्यागम (0);

		/* write the entry */
		यदि (atomicio(vwrite, fd, &चरमः, परिमाण(चरमः)) != परिमाण(चरमः)) {
			close(fd);
			logit("%s: Error writing to %s: %s", __func__,
			    LASTLOG_FILE, strerror(errno));
			प्रत्यागम (0);
		}

		close(fd);
		प्रत्यागम (1);
	स्वभाव:
		logit_f("Invalid type field");
		प्रत्यागम (0);
	}
}
#यदि_अन्तः /* LASTLOG_WRITE_PUTUTXLINE */

#यदि_परिभाषितम् HAVE_GETLASTLOGXBYNAME
पूर्णाङ्क
lastlog_get_प्रविष्टिः(संरचना logininfo *li)
{
	संरचना lastlogx l, *ll;

	यदि ((ll = getlastlogxbyname(li->username, &l)) == रिक्त) {
		स्मृतिं_पूरय(&l, '\0', परिमाण(l));
		ll = &l;
	}
	पङ्क्तिः_fullname(li->पङ्क्तिः, ll->ll_पङ्क्तिः, परिमाण(li->पङ्क्तिः));
	strlcpy(li->hostname, ll->ll_host,
		MIN_SIZEOF(li->hostname, ll->ll_host));
	li->tv_sec = ll->ll_tv.tv_sec;
	li->tv_usec = ll->ll_tv.tv_usec;
	प्रत्यागम (1);
}
#अन्यथा /* HAVE_GETLASTLOGXBYNAME */
पूर्णाङ्क
lastlog_get_प्रविष्टिः(संरचना logininfo *li)
{
	संरचना lastlog चरमः;
	पूर्णाङ्क fd, ret;

	यदि (!lastlog_openseek(li, &fd, O_RDONLY))
		प्रत्यागम (0);

	ret = atomicio(पठ, fd, &चरमः, परिमाण(चरमः));
	close(fd);

	विकल्प (ret) {
	पक्ष 0:
		स्मृतिं_पूरय(&चरमः, '\0', परिमाण(चरमः));
		/* FALLTHRU */
	पक्ष परिमाण(चरमः):
		पङ्क्तिः_fullname(li->पङ्क्तिः, चरमः.ll_पङ्क्तिः, परिमाण(li->पङ्क्तिः));
		strlcpy(li->hostname, चरमः.ll_host,
		    MIN_SIZEOF(li->hostname, चरमः.ll_host));
		li->tv_sec = चरमः.ll_time;
		प्रत्यागम (1);
	पक्ष -1:
		error("%s: Error reading from %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		प्रत्यागम (0);
	स्वभाव:
		error("%s: Error reading from %s: Expecting %d, got %d",
		    __func__, LASTLOG_FILE, (पूर्णाङ्क)परिमाण(चरमः), ret);
		प्रत्यागम (0);
	}

	/* NOTREACHED */
	प्रत्यागम (0);
}
#यदि_अन्तः /* HAVE_GETLASTLOGXBYNAME */
#यदि_अन्तः /* USE_LASTLOG */

#यदि defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
पूर्णाङ्क
utmpx_get_प्रविष्टिः(संरचना logininfo *li)
{
	संरचना utmpx *utx;

	यदि (setutxdb(UTXDB_LASTLOGIN, रिक्त) != 0)
		प्रत्यागम (0);
	utx = getutxuser(li->username);
	यदि (utx == रिक्त) {
		endutxent();
		प्रत्यागम (0);
	}

	पङ्क्तिः_fullname(li->पङ्क्तिः, utx->ut_पङ्क्तिः,
	    MIN_SIZEOF(li->पङ्क्तिः, utx->ut_पङ्क्तिः));
	strlcpy(li->hostname, utx->ut_host,
	    MIN_SIZEOF(li->hostname, utx->ut_host));
	li->tv_sec = utx->ut_tv.tv_sec;
	li->tv_usec = utx->ut_tv.tv_usec;
	endutxent();
	प्रत्यागम (1);
}
#यदि_अन्तः /* USE_UTMPX && HAVE_SETUTXDB && UTXDB_LASTLOGIN && HAVE_GETUTXUSER */

#यदि_परिभाषितम् USE_BTMP
/*
 * Logs failed login attempts in _PATH_BTMP if that exists.
 * The most common login failure is to give password instead of username.
 * So the _PATH_BTMP file is checked for the correct permission, so that only
 * root can read it.
 */
शून्य
लेखः_failed_login(संरचना ssh *ssh, ध्रुव वर्ण *username, ध्रुव वर्ण *hostname,
    ध्रुव वर्ण *ttyn)
{
	पूर्णाङ्क fd;
	संरचना utmp ut;
	संरचना logininfo li;
	socklen_t fromlen = परिमाण(li.hostaddr);
	time_t t;
	संरचना stat fst;

	यदि (geteuid() != 0)
		प्रत्यागम;
	यदि ((fd = उद्घाटय(मार्गः_BTMP, O_WRONLY | O_APPEND)) < 0) {
		debug("Unable to open the btmp file %s: %s", मार्गः_BTMP,
		    strerror(errno));
		प्रत्यागम;
	}
	यदि (fstat(fd, &fst) < 0) {
		logit("%s: fstat of %s failed: %s", __func__, मार्गः_BTMP,
		    strerror(errno));
		गच्छ बहिर्गमनम्;
	}
	यदि ((fst.st_mode & (S_IXGRP | S_IRWXO)) || fst.st_uid != 0) {
		logit("Excess permission or bad ownership on file %s",
		    मार्गः_BTMP);
		गच्छ बहिर्गमनम्;
	}

	/* Construct a logininfo and turn it into a utmp */
	स्मृतिं_पूरय(&li, 0, परिमाण(li));
	li.type = LTYPE_FAILED;
	li.pid = getpid();
	strlcpy(li.पङ्क्तिः, "ssh:notty", परिमाण(li.पङ्क्तिः));
	strlcpy(li.username, username, परिमाण(li.username));
	strlcpy(li.hostname, hostname, परिमाण(li.hostname));
	time(&t);
	li.tv_sec = t > 0 ? (अचिह्नित दीर्घ)t : 0;
	यदि (ssh_packet_connection_is_on_socket(ssh)) {
		(शून्य)getpeername(ssh_packet_get_connection_अन्तर्(ssh),
		    &li.hostaddr.sa, &fromlen);
	}
	construct_utmp(&li, &ut);

	यदि (atomicio(vwrite, fd, &ut, परिमाण(ut)) != परिमाण(ut)) {
		error("Failed to write to %s: %s", मार्गः_BTMP,
		    strerror(errno));
	}
बहिर्गमनम्:
	close(fd);
}
#यदि_अन्तः	/* USE_BTMP */
