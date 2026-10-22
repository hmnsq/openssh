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

#ifdef USE_WTMPDB
# include <wtmpdb.h>
#endif

/**
 ** prototypes for helper functions in this file
 **/

#जर HAVE_UTMP_H
शून्य set_utmp_time(संरचना logininfo *li, संरचना utmp *ut);
शून्य construct_utmp(संरचना logininfo *li, संरचना utmp *ut);
#endif

#ifdef HAVE_UTMPX_H
शून्य set_utmpx_time(संरचना logininfo *li, संरचना utmpx *ut);
शून्य construct_utmpx(संरचना logininfo *li, संरचना utmpx *ut);
#endif

पूर्णांक utmp_write_entry(संरचना logininfo *li);
पूर्णांक utmpx_write_entry(संरचना logininfo *li);
पूर्णांक wtmp_write_entry(संरचना logininfo *li);
पूर्णांक wtmpx_write_entry(संरचना logininfo *li);
पूर्णांक lastlog_write_entry(संरचना logininfo *li);
पूर्णांक syslogin_write_entry(संरचना logininfo *li);
#ifdef USE_WTMPDB
पूर्णांक wtmpdb_write_entry(संरचना logininfo *li);
#endif

पूर्णांक getlast_entry(संरचना logininfo *li);
पूर्णांक lastlog_get_entry(संरचना logininfo *li);
पूर्णांक utmpx_get_entry(संरचना logininfo *li);
पूर्णांक wtmp_get_entry(संरचना logininfo *li);
पूर्णांक wtmpx_get_entry(संरचना logininfo *li);

बाह्य संरचना sshbuf *loginmsg;

/* pick the shortest string */
#define MIN_SIZEOF(s1,s2) (आकार(s1) < आकार(s2) ? आकार(s1) : आकार(s2))

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
पूर्णांक
login_login(संरचना logininfo *li)
{
	li->type = LTYPE_LOGIN;
	परत (login_write(li));
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
पूर्णांक
login_logout(संरचना logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	परत (login_write(li));
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
अचिन्हित पूर्णांक
login_get_lastlog_time(स्थिरांक uid_t uid)
{
	संरचना logininfo li;

	जर (login_get_lastlog(&li, uid))
		परत (li.tv_sec);
	अन्यथा
		परत (0);
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
login_get_lastlog(संरचना logininfo *li, स्थिरांक uid_t uid)
{
	संरचना passwd *pw;

	स_रखो(li, '\0', आकार(*li));
	li->uid = uid;

	/*
	 * If we don't have a 'real' lastlog, we need the username to
	 * reliably search wtmp(x) for the last login (see
	 * wtmp_get_entry().)
	 */
	pw = getpwuid(uid);
	जर (pw == रिक्त)
		fatal("%s: Cannot find account for uid %ld", __func__,
		    (दीर्घ)uid);

	जर (strlcpy(li->username, pw->pw_name, आकार(li->username)) >=
	    आकार(li->username)) {
		error("%s: username too long (%lu > max %lu)", __func__,
		    (अचिन्हित दीर्घ)म_माप(pw->pw_name),
		    (अचिन्हित दीर्घ)आकार(li->username) - 1);
		परत रिक्त;
	}

	जर (getlast_entry(li))
		परत (li);
	अन्यथा
		परत (रिक्त);
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
logininfo *login_alloc_entry(pid_t pid, स्थिरांक अक्षर *username,
    स्थिरांक अक्षर *hostname, स्थिरांक अक्षर *ओळ)
{
	संरचना logininfo *newli;

	newli = xmalloc(आकार(*newli));
	login_init_entry(newli, pid, username, hostname, ओळ);
	परत (newli);
}


/* login_free_entry(struct logininfo *)    - free struct memory */
शून्य
login_free_entry(संरचना logininfo *li)
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
पूर्णांक
login_init_entry(संरचना logininfo *li, pid_t pid, स्थिरांक अक्षर *username,
    स्थिरांक अक्षर *hostname, स्थिरांक अक्षर *ओळ)
{
	संरचना passwd *pw;

	स_रखो(li, 0, आकार(*li));

	li->pid = pid;

	/* set the line information */
	जर (ओळ)
		ओळ_fullname(li->ओळ, ओळ, आकार(li->ओळ));

	जर (username) {
		strlcpy(li->username, username, आकार(li->username));
		pw = getpwnam(li->username);
		जर (pw == रिक्त) {
			fatal("%s: Cannot find user \"%s\"", __func__,
			    li->username);
		}
		li->uid = pw->pw_uid;
	}

	जर (hostname)
		strlcpy(li->hostname, hostname, आकार(li->hostname));

	परत (1);
}

/*
 * login_set_current_time(struct logininfo *)    - set the current time
 *
 * Set the current time in a logininfo structure. This function is
 * meant to eliminate the need to deal with system dependencies for
 * time handling.
 */
शून्य
login_set_current_time(संरचना logininfo *li)
{
	संरचना timeval tv;

	gettimeofday(&tv, रिक्त);

	li->tv_sec = tv.tv_sec;
	li->tv_usec = tv.tv_usec;
}

/* copy a sockaddr_* into our logininfo */
शून्य
login_set_addr(संरचना logininfo *li, स्थिरांक संरचना sockaddr *sa,
    स्थिरांक अचिन्हित पूर्णांक sa_size)
{
	अचिन्हित पूर्णांक bufsize = sa_size;

	/* make sure we don't overrun our union */
	जर (आकार(li->hostaddr) < sa_size)
		bufsize = आकार(li->hostaddr);

	स_नकल(&li->hostaddr.sa, sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/
पूर्णांक
login_write(संरचना logininfo *li)
{
#ifndef HAVE_CYGWIN
	जर (geteuid() != 0) {
		logit("Attempt to write login records by non-root user (aborting)");
		परत (1);
	}
#endif

	/* set the timestamp */
	login_set_current_time(li);
#ifdef USE_LOGIN
	syslogin_write_entry(li);
#endif
#ifdef USE_LASTLOG
	जर (li->type == LTYPE_LOGIN)
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
	जर (li->type == LTYPE_LOGIN &&
	    !sys_auth_record_login(li->username,li->hostname,li->ओळ,
	    loginmsg))
		logit("Writing login record failed for %s", li->username);
#endif
#ifdef SSH_AUDIT_EVENTS
	जर (li->type == LTYPE_LOGIN)
		audit_session_open(li);
	अन्यथा जर (li->type == LTYPE_LOGOUT)
		audit_session_close(li);
#endif
	परत (0);
}

#ifdef LOGIN_NEEDS_UTMPX
पूर्णांक
login_utmp_only(संरचना logininfo *li)
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
	परत (0);
}
#endif

/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
पूर्णांक
getlast_entry(संरचना logininfo *li)
{
#ifdef USE_LASTLOG
	परत(lastlog_get_entry(li));
#अन्यथा /* !USE_LASTLOG */
#जर defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
	परत (utmpx_get_entry(li));
#endif

#जर defined(DISABLE_LASTLOG)
	/* On some systems we shouldn't even try to obtain last login
	 * time, e.g. AIX */
	परत (0);
# elif defined(USE_WTMP) && \
    (defined(HAVE_TIME_IN_UTMP) || defined(HAVE_TV_IN_UTMP))
	/* retrieve last login time from utmp */
	परत (wtmp_get_entry(li));
# elif defined(USE_WTMPX) && \
    (defined(HAVE_TIME_IN_UTMPX) || defined(HAVE_TV_IN_UTMPX))
	/* If wtmp isn't available, try wtmpx */
	परत (wtmpx_get_entry(li));
# अन्यथा
	/* Give up: No means of retrieving last login time */
	परत (0);
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
अक्षर *
ओळ_fullname(अक्षर *dst, स्थिरांक अक्षर *src, u_int dstsize)
{
	स_रखो(dst, '\0', dstsize);
	जर ((म_भेदन(src, "/dev/", 5) == 0) || (dstsize < (म_माप(src) + 5)))
		strlcpy(dst, src, dstsize);
	अन्यथा {
		strlcpy(dst, "/dev/", dstsize);
		strlcat(dst, src, dstsize);
	}
	परत (dst);
}

/* line_stripname(): strip the leading '/dev' if it exists, return dst */
अक्षर *
ओळ_stripname(अक्षर *dst, स्थिरांक अक्षर *src, पूर्णांक dstsize)
{
	स_रखो(dst, '\0', dstsize);
	जर (म_भेदन(src, "/dev/", 5) == 0)
		strlcpy(dst, src + 5, dstsize);
	अन्यथा
		strlcpy(dst, src, dstsize);
	परत (dst);
}

/*
 * line_abbrevname(): Return the abbreviated (usually four-character)
 * form of the line (Just use the last <dstsize> characters of the
 * full name.)
 *
 * NOTE: use strncpy because we do NOT necessarily want zero
 * termination
 */
अक्षर *
ओळ_abbrevname(अक्षर *dst, स्थिरांक अक्षर *src, पूर्णांक dstsize)
{
	माप_प्रकार len;

	स_रखो(dst, '\0', dstsize);

	जर (म_भेद(src, "ssh:notty") == 0)
		परत dst;

	/* Always skip prefix if present */
	जर (म_भेदन(src, "/dev/", 5) == 0)
		src += 5;

#ifdef WITH_ABBREV_NO_TTY
	जर (म_भेदन(src, "tty", 3) == 0)
		src += 3;
#endif

	len = म_माप(src);

	जर (len > 0) {
		जर (((पूर्णांक)len - dstsize) > 0)
			src +=  ((पूर्णांक)len - dstsize);

		/* note: _don't_ change this to strlcpy */
		म_नकलन(dst, src, (माप_प्रकार)dstsize);
	}

	परत (dst);
}

/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#जर defined(USE_BTMP) || defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
शून्य
set_utmp_time(संरचना logininfo *li, संरचना utmp *ut)
{
# जर defined(HAVE_TV_IN_UTMP)
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMP)
	ut->ut_time = li->tv_sec;
# endif
}

शून्य
construct_utmp(संरचना logininfo *li,
		    संरचना utmp *ut)
{
# ifdef HAVE_ADDR_V6_IN_UTMP
	संरचना sockaddr_in6 *sa6;
# endif

	स_रखो(ut, '\0', आकार(*ut));

	/* First fill out fields used for both logins and logouts */

# ifdef HAVE_ID_IN_UTMP
	ओळ_abbrevname(ut->ut_id, li->ओळ, आकार(ut->ut_id));
# endif

# ifdef HAVE_TYPE_IN_UTMP
	/* This is done here to keep utmp constants out of struct logininfo */
	निवड (li->type) {
	स्थिती LTYPE_FAILED:
		ut->ut_type = LOGIN_PROCESS;
		थांबा;
	स्थिती LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		थांबा;
	स्थिती LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		थांबा;
	}
# endif
	set_utmp_time(li, ut);

	ओळ_stripname(ut->ut_ओळ, li->ओळ, आकार(ut->ut_ओळ));

# ifdef HAVE_PID_IN_UTMP
	ut->ut_pid = li->pid;
# endif

	/* If we're logging out, leave all other fields blank */
	जर (li->type == LTYPE_LOGOUT)
		परत;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

	/* Use strncpy because we don't necessarily want null termination */
	म_नकलन(ut->ut_name, li->username,
	    MIN_SIZEOF(ut->ut_name, li->username));
# ifdef HAVE_HOST_IN_UTMP
	म_नकलन(ut->ut_host, li->hostname,
	    MIN_SIZEOF(ut->ut_host, li->hostname));
# endif
# ifdef HAVE_ADDR_IN_UTMP
	/* this is just a 32-bit IP address */
	जर (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMP
	/* this is just a 128-bit IPv6 address */
	जर (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((संरचना sockaddr_in6 *)&li->hostaddr.sa);
		स_नकल(ut->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		जर (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
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

#जर defined(USE_UTMPX) || defined (USE_WTMPX)
/* build the utmpx structure */
शून्य
set_utmpx_time(संरचना logininfo *li, संरचना utmpx *utx)
{
# जर defined(HAVE_TV_IN_UTMPX)
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMPX)
	utx->ut_time = li->tv_sec;
# endif
}

शून्य
construct_utmpx(संरचना logininfo *li, संरचना utmpx *utx)
{
# ifdef HAVE_ADDR_V6_IN_UTMPX
	संरचना sockaddr_in6 *sa6;
#  endif
	स_रखो(utx, '\0', आकार(*utx));

# ifdef HAVE_ID_IN_UTMPX
	ओळ_abbrevname(utx->ut_id, li->ओळ, आकार(utx->ut_id));
# endif

	/* this is done here to keep utmp constants out of loginrec.h */
	निवड (li->type) {
	स्थिती LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		थांबा;
	स्थिती LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		थांबा;
	}
	ओळ_stripname(utx->ut_ओळ, li->ओळ, आकार(utx->ut_ओळ));
	set_utmpx_time(li, utx);
	utx->ut_pid = li->pid;

	/* strncpy(): Don't necessarily want null termination */
	म_नकलन(utx->ut_user, li->username,
	    MIN_SIZEOF(utx->ut_user, li->username));

	जर (li->type == LTYPE_LOGOUT)
		परत;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

# ifdef HAVE_HOST_IN_UTMPX
	म_नकलन(utx->ut_host, li->hostname,
	    MIN_SIZEOF(utx->ut_host, li->hostname));
# endif
# ifdef HAVE_SS_IN_UTMPX
	utx->ut_ss = li->hostaddr.sa_storage;
# endif
# ifdef HAVE_ADDR_IN_UTMPX
	/* this is just a 32-bit IP address */
	जर (li->hostaddr.sa.sa_family == AF_INET)
		utx->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMPX
	/* this is just a 128-bit IPv6 address */
	जर (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((संरचना sockaddr_in6 *)&li->hostaddr.sa);
		स_नकल(utx->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		जर (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			utx->ut_addr_v6[0] = utx->ut_addr_v6[3];
			utx->ut_addr_v6[1] = 0;
			utx->ut_addr_v6[2] = 0;
			utx->ut_addr_v6[3] = 0;
		}
	}
# endif
# ifdef HAVE_SYSLEN_IN_UTMPX
	/* ut_syslen is the length of the utx_host string */
	utx->ut_syslen = MINIMUM(म_माप(li->hostname), आकार(utx->ut_host));
# endif
}
#endif /* USE_UTMPX || USE_WTMPX */

/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */
#ifdef USE_UTMP

/* if we can, use pututline() etc. */
# जर !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
	defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
# endif


/* write a utmp entry with the system's help (pututline() and pals) */
# ifdef UTMP_USE_LIBRARY
स्थिर पूर्णांक
utmp_write_library(संरचना logininfo *li, संरचना utmp *ut)
{
	setutent();
	pututline(ut);
#  ifdef HAVE_ENDUTENT
	endutent();
#  endif
	परत (1);
}
# अन्यथा /* UTMP_USE_LIBRARY */

/*
 * Write a utmp entry direct to the file
 * This is a slightly modification of code in OpenBSD's login.c
 */
स्थिर पूर्णांक
utmp_write_direct(संरचना logininfo *li, संरचना utmp *ut)
{
	संरचना utmp old_ut;
	नोंदणी पूर्णांक fd;
	पूर्णांक tty;

	/* FIXME: (ATL) ttyslot() needs local implementation */

#जर defined(HAVE_GETTTYENT)
	संरचना ttyent *ty;

	tty=0;
	setttyent();
	पर्यंत (रिक्त != (ty = getttyent())) {
		tty++;
		जर (!म_भेदन(ty->ty_name, ut->ut_ओळ, आकार(ut->ut_ओळ)))
			थांबा;
	}
	endttyent();

	जर (रिक्त == ty) {
		logit_f("tty not found");
		परत (0);
	}
#अन्यथा /* FIXME */

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

#endif /* HAVE_GETTTYENT */

	जर (tty > 0 && (fd = खोलो(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		off_t pos, ret;

		pos = (off_t)tty * आकार(संरचना utmp);
		जर ((ret = lseek(fd, pos, शुरू_से)) == -1) {
			logit_f("lseek: %s", म_त्रुटि(त्रुटि_सं));
			बंद(fd);
			परत (0);
		}
		जर (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			बंद(fd);
			परत (0);
		}
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		जर (atomicio(पठ, fd, &old_ut, आकार(old_ut)) == आकार(old_ut) &&
		    (ut->ut_host[0] == '\0') && (old_ut.ut_host[0] != '\0') &&
		    (म_भेदन(old_ut.ut_ओळ, ut->ut_ओळ, आकार(ut->ut_ओळ)) == 0) &&
		    (म_भेदन(old_ut.ut_name, ut->ut_name, आकार(ut->ut_name)) == 0))
			स_नकल(ut->ut_host, old_ut.ut_host, आकार(ut->ut_host));

		जर ((ret = lseek(fd, pos, शुरू_से)) == -1) {
			logit_f("lseek: %s", म_त्रुटि(त्रुटि_सं));
			बंद(fd);
			परत (0);
		}
		जर (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			बंद(fd);
			परत (0);
		}
		जर (atomicio(vwrite, fd, ut, आकार(*ut)) != आकार(*ut)) {
			logit("%s: error writing %s: %s", __func__,
			    UTMP_FILE, म_त्रुटि(त्रुटि_सं));
			बंद(fd);
			परत (0);
		}

		बंद(fd);
		परत (1);
	} अन्यथा {
		परत (0);
	}
}
# endif /* UTMP_USE_LIBRARY */

स्थिर पूर्णांक
utmp_perform_login(संरचना logininfo *li)
{
	संरचना utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	जर (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		परत (0);
	}
# अन्यथा
	जर (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		परत (0);
	}
# endif
	परत (1);
}


स्थिर पूर्णांक
utmp_perform_logout(संरचना logininfo *li)
{
	संरचना utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	जर (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		परत (0);
	}
# अन्यथा
	जर (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		परत (0);
	}
# endif
	परत (1);
}


पूर्णांक
utmp_write_entry(संरचना logininfo *li)
{
	निवड(li->type) {
	स्थिती LTYPE_LOGIN:
		परत (utmp_perform_login(li));

	स्थिती LTYPE_LOGOUT:
		परत (utmp_perform_logout(li));

	पूर्वनिर्धारित:
		logit_f("invalid type field");
		परत (0);
	}
}
#endif /* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#ifdef USE_UTMPX

/* if we have the wherewithal, use pututxline etc. */
# जर !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) && \
	defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
# endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
# ifdef UTMPX_USE_LIBRARY
स्थिर पूर्णांक
utmpx_write_library(संरचना logininfo *li, संरचना utmpx *utx)
{
	setutxent();
	pututxline(utx);

#  ifdef HAVE_ENDUTXENT
	endutxent();
#  endif
	परत (1);
}

# अन्यथा /* UTMPX_USE_LIBRARY */

/* write a utmp entry direct to the file */
स्थिर पूर्णांक
utmpx_write_direct(संरचना logininfo *li, संरचना utmpx *utx)
{
	logit_f("not implemented!");
	परत (0);
}
# endif /* UTMPX_USE_LIBRARY */

स्थिर पूर्णांक
utmpx_perform_login(संरचना logininfo *li)
{
	संरचना utmpx utx;

	construct_utmpx(li, &utx);
# ifdef UTMPX_USE_LIBRARY
	जर (!utmpx_write_library(li, &utx)) {
		logit_f("utmp_write_library() failed");
		परत (0);
	}
# अन्यथा
	जर (!utmpx_write_direct(li, &utx)) {
		logit_f("utmp_write_direct() failed");
		परत (0);
	}
# endif
	परत (1);
}


स्थिर पूर्णांक
utmpx_perform_logout(संरचना logininfo *li)
{
	संरचना utmpx utx;

	construct_utmpx(li, &utx);
# ifdef HAVE_ID_IN_UTMPX
	ओळ_abbrevname(utx.ut_id, li->ओळ, आकार(utx.ut_id));
# endif
# ifdef HAVE_TYPE_IN_UTMPX
	utx.ut_type = DEAD_PROCESS;
# endif

# ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
# अन्यथा
	utmpx_write_direct(li, &utx);
# endif
	परत (1);
}

पूर्णांक
utmpx_write_entry(संरचना logininfo *li)
{
	निवड(li->type) {
	स्थिती LTYPE_LOGIN:
		परत (utmpx_perform_login(li));
	स्थिती LTYPE_LOGOUT:
		परत (utmpx_perform_logout(li));
	पूर्वनिर्धारित:
		logit_f("invalid type field");
		परत (0);
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
स्थिर पूर्णांक
wtmp_write(संरचना logininfo *li, संरचना utmp *ut)
{
	संरचना stat buf;
	पूर्णांक fd, ret = 1;

	जर ((fd = खोलो(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem writing %s: %s", __func__,
		    WTMP_FILE, म_त्रुटि(त्रुटि_सं));
		परत (0);
	}
	जर (ख_स्थिति(fd, &buf) == 0)
		जर (atomicio(vwrite, fd, ut, आकार(*ut)) != आकार(*ut)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMP_FILE, म_त्रुटि(त्रुटि_सं));
			ret = 0;
		}
	बंद(fd);
	परत (ret);
}

स्थिर पूर्णांक
wtmp_perform_login(संरचना logininfo *li)
{
	संरचना utmp ut;

	construct_utmp(li, &ut);
	परत (wtmp_write(li, &ut));
}


स्थिर पूर्णांक
wtmp_perform_logout(संरचना logininfo *li)
{
	संरचना utmp ut;

	construct_utmp(li, &ut);
	परत (wtmp_write(li, &ut));
}


पूर्णांक
wtmp_write_entry(संरचना logininfo *li)
{
	निवड(li->type) {
	स्थिती LTYPE_LOGIN:
		परत (wtmp_perform_login(li));
	स्थिती LTYPE_LOGOUT:
		परत (wtmp_perform_logout(li));
	पूर्वनिर्धारित:
		logit_f("invalid type field");
		परत (0);
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
स्थिर पूर्णांक
wtmp_islogin(संरचना logininfo *li, संरचना utmp *ut)
{
	जर (म_भेदन(li->username, ut->ut_name,
	    MIN_SIZEOF(li->username, ut->ut_name)) == 0) {
# ifdef HAVE_TYPE_IN_UTMP
		जर (ut->ut_type & USER_PROCESS)
			परत (1);
# अन्यथा
		परत (1);
# endif
	}
	परत (0);
}

पूर्णांक
wtmp_get_entry(संरचना logininfo *li)
{
	संरचना stat st;
	संरचना utmp ut;
	पूर्णांक fd, found = 0;

	/* Clear the time entries in our logininfo */
	li->tv_sec = li->tv_usec = 0;

	जर ((fd = खोलो(WTMP_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMP_FILE, म_त्रुटि(त्रुटि_सं));
		परत (0);
	}
	जर (ख_स्थिति(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMP_FILE, म_त्रुटि(त्रुटि_सं));
		बंद(fd);
		परत (0);
	}

	/* Seek to the start of the last struct utmp */
	जर (lseek(fd, -(off_t)आकार(संरचना utmp), अंत_से) == -1) {
		/* Looks like we've got a fresh wtmp file */
		बंद(fd);
		परत (0);
	}

	पर्यंत (!found) {
		जर (atomicio(पठ, fd, &ut, आकार(ut)) != आकार(ut)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMP_FILE, म_त्रुटि(त्रुटि_सं));
			बंद (fd);
			परत (0);
		}
		जर (wtmp_islogin(li, &ut) ) {
			found = 1;
			/*
			 * We've already checked for a time in struct
			 * utmp, in login_getlast()
			 */
# ifdef HAVE_TIME_IN_UTMP
			li->tv_sec = ut.ut_time;
# अन्यथा
#  जर HAVE_TV_IN_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
# endif
			ओळ_fullname(li->ओळ, ut.ut_ओळ,
			    MIN_SIZEOF(li->ओळ, ut.ut_ओळ));
# ifdef HAVE_HOST_IN_UTMP
			strlcpy(li->hostname, ut.ut_host,
			    MIN_SIZEOF(li->hostname, ut.ut_host));
# endif
			सुरूठेवा;
		}
		/* Seek back 2 x struct utmp */
		जर (lseek(fd, -(off_t)(2 * आकार(संरचना utmp)), प्रस्तुत_से) == -1) {
			/* We've found the start of the file, so quit */
			बंद(fd);
			परत (0);
		}
	}

	/* We found an entry. Tidy up and return */
	बंद(fd);
	परत (1);
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
स्थिर पूर्णांक
wtmpx_write(संरचना logininfo *li, संरचना utmpx *utx)
{
#ifndef HAVE_UPDWTMPX
	संरचना stat buf;
	पूर्णांक fd, ret = 1;

	जर ((fd = खोलो(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, म_त्रुटि(त्रुटि_सं));
		परत (0);
	}

	जर (ख_स्थिति(fd, &buf) == 0)
		जर (atomicio(vwrite, fd, utx, आकार(*utx)) != आकार(*utx)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMPX_FILE, म_त्रुटि(त्रुटि_सं));
			ret = 0;
		}
	बंद(fd);

	परत (ret);
#अन्यथा
	updwtmpx(WTMPX_FILE, utx);
	परत (1);
#endif
}


स्थिर पूर्णांक
wtmpx_perform_login(संरचना logininfo *li)
{
	संरचना utmpx utx;

	construct_utmpx(li, &utx);
	परत (wtmpx_write(li, &utx));
}


स्थिर पूर्णांक
wtmpx_perform_logout(संरचना logininfo *li)
{
	संरचना utmpx utx;

	construct_utmpx(li, &utx);
	परत (wtmpx_write(li, &utx));
}


पूर्णांक
wtmpx_write_entry(संरचना logininfo *li)
{
	निवड(li->type) {
	स्थिती LTYPE_LOGIN:
		परत (wtmpx_perform_login(li));
	स्थिती LTYPE_LOGOUT:
		परत (wtmpx_perform_logout(li));
	पूर्वनिर्धारित:
		logit_f("invalid type field");
		परत (0);
	}
}

/* Please see the notes above wtmp_islogin() for information about the
   next two functions */

/* Return true if this wtmpx entry indicates a login */
स्थिर पूर्णांक
wtmpx_islogin(संरचना logininfo *li, संरचना utmpx *utx)
{
	जर (म_भेदन(li->username, utx->ut_user,
	    MIN_SIZEOF(li->username, utx->ut_user)) == 0 ) {
# ifdef HAVE_TYPE_IN_UTMPX
		जर (utx->ut_type == USER_PROCESS)
			परत (1);
# अन्यथा
		परत (1);
# endif
	}
	परत (0);
}


पूर्णांक
wtmpx_get_entry(संरचना logininfo *li)
{
	संरचना stat st;
	संरचना utmpx utx;
	पूर्णांक fd, found=0;

	/* Clear the time entries */
	li->tv_sec = li->tv_usec = 0;

	जर ((fd = खोलो(WTMPX_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, म_त्रुटि(त्रुटि_सं));
		परत (0);
	}
	जर (ख_स्थिति(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMPX_FILE, म_त्रुटि(त्रुटि_सं));
		बंद(fd);
		परत (0);
	}

	/* Seek to the start of the last struct utmpx */
	जर (lseek(fd, -(off_t)आकार(संरचना utmpx), अंत_से) == -1 ) {
		/* probably a newly rotated wtmpx file */
		बंद(fd);
		परत (0);
	}

	पर्यंत (!found) {
		जर (atomicio(पठ, fd, &utx, आकार(utx)) != आकार(utx)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMPX_FILE, म_त्रुटि(त्रुटि_सं));
			बंद (fd);
			परत (0);
		}
		/*
		 * Logouts are recorded as a blank username on a particular
		 * line. So, we just need to find the username in struct utmpx
		 */
		जर (wtmpx_islogin(li, &utx)) {
			found = 1;
# जर defined(HAVE_TV_IN_UTMPX)
			li->tv_sec = utx.ut_tv.tv_sec;
# elif defined(HAVE_TIME_IN_UTMPX)
			li->tv_sec = utx.ut_time;
# endif
			ओळ_fullname(li->ओळ, utx.ut_ओळ, आकार(li->ओळ));
# जर defined(HAVE_HOST_IN_UTMPX)
			strlcpy(li->hostname, utx.ut_host,
			    MIN_SIZEOF(li->hostname, utx.ut_host));
# endif
			सुरूठेवा;
		}
		जर (lseek(fd, -(off_t)(2 * आकार(संरचना utmpx)), प्रस्तुत_से) == -1) {
			बंद(fd);
			परत (0);
		}
	}

	बंद(fd);
	परत (1);
}
#endif /* USE_WTMPX */

#ifdef USE_WTMPDB
स्थिर पूर्णांक
wtmpdb_perform_login(संरचना logininfo *li)
{
	uint64_t login_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	    li->tv_usec;
	स्थिरांक अक्षर *tty;

	जर (म_भेदन(li->ओळ, "/dev/", 5) == 0)
		tty = &(li->ओळ[5]);
	अन्यथा
		tty = li->ओळ;

	li->wtmpdb_id = wtmpdb_login(रिक्त, USER_PROCESS, li->username,
	    login_time, tty, li->hostname, 0, 0);

	जर (li->wtmpdb_id < 0)
		परत (0);

	परत (1);
}

स्थिर पूर्णांक
wtmpdb_perform_logout(संरचना logininfo *li)
{
	uint64_t logout_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	   li->tv_usec;

	जर (li->wtmpdb_id == 0) {
		स्थिरांक अक्षर *tty;

		जर (म_भेदन(li->ओळ, "/dev/", 5) == 0)
			tty = &(li->ओळ[5]);
		अन्यथा
			tty = li->ओळ;

		li->wtmpdb_id = wtmpdb_get_id(रिक्त, tty, रिक्त);
	}
	wtmpdb_logout(रिक्त, li->wtmpdb_id, logout_time, रिक्त);

	परत (1);
}

पूर्णांक
wtmpdb_write_entry(संरचना logininfo *li)
{
	निवड(li->type) {
	स्थिती LTYPE_LOGIN:
		परत (wtmpdb_perform_login(li));
	स्थिती LTYPE_LOGOUT:
		परत (wtmpdb_perform_logout(li));
	पूर्वनिर्धारित:
		logit_f("invalid type field");
		परत (0);
	}
}
#endif

/**
 ** Low-level libutil login() functions
 **/

#ifdef USE_LOGIN
स्थिर पूर्णांक
syslogin_perform_login(संरचना logininfo *li)
{
	संरचना utmp *ut;

	ut = xmalloc(आकार(*ut));
	construct_utmp(li, ut);
	login(ut);
	मुक्त(ut);

	परत (1);
}

स्थिर पूर्णांक
syslogin_perform_logout(संरचना logininfo *li)
{
# ifdef HAVE_LOGOUT
	अक्षर ओळ[UT_LINESIZE];

	(शून्य)ओळ_stripname(ओळ, li->ओळ, आकार(ओळ));

	जर (!logout(ओळ))
		logit_f("logout() returned an error");
#  ifdef HAVE_LOGWTMP
	अन्यथा
		logwtmp(ओळ, "", "");
#  endif
	/* FIXME: (ATL - if the need arises) What to do if we have
	 * login, but no logout?  what if logout but no logwtmp? All
	 * routines are in libutil so they should all be there,
	 * but... */
# endif
	परत (1);
}

पूर्णांक
syslogin_write_entry(संरचना logininfo *li)
{
	निवड (li->type) {
	स्थिती LTYPE_LOGIN:
		परत (syslogin_perform_login(li));
	स्थिती LTYPE_LOGOUT:
		परत (syslogin_perform_logout(li));
	पूर्वनिर्धारित:
		logit_f("Invalid type field");
		परत (0);
	}
}
#endif /* USE_LOGIN */

/* end of file log-syslogin.c */

/**
 ** Low-level lastlog functions
 **/

#ifdef USE_LASTLOG

#जर !defined(LASTLOG_WRITE_PUTUTXLINE) || !defined(HAVE_GETLASTLOGXBYNAME)
/* open the file (using filemode) and seek to the login entry */
स्थिर पूर्णांक
lastlog_openseek(संरचना logininfo *li, पूर्णांक *fd, पूर्णांक filemode)
{
	off_t offset;
	अक्षर lastlog_file[1024];
	संरचना stat st;

	जर (stat(LASTLOG_FILE, &st) != 0) {
		logit("%s: Couldn't stat %s: %s", __func__,
		    LASTLOG_FILE, म_त्रुटि(त्रुटि_सं));
		परत (0);
	}
	जर (S_ISDIR(st.st_mode)) {
		snprintf(lastlog_file, आकार(lastlog_file), "%s/%s",
		    LASTLOG_FILE, li->username);
	} अन्यथा जर (S_ISREG(st.st_mode)) {
		strlcpy(lastlog_file, LASTLOG_FILE, आकार(lastlog_file));
	} अन्यथा {
		logit("%s: %.100s is not a file or directory!", __func__,
		    LASTLOG_FILE);
		परत (0);
	}

	*fd = खोलो(lastlog_file, filemode, 0600);
	जर (*fd < 0) {
		debug("%s: Couldn't open %s: %s", __func__,
		    lastlog_file, म_त्रुटि(त्रुटि_सं));
		परत (0);
	}

	जर (S_ISREG(st.st_mode)) {
		/* find this uid's offset in the lastlog file */
		offset = (off_t) ((u_long)li->uid * आकार(संरचना lastlog));

		जर (lseek(*fd, offset, शुरू_से) != offset) {
			logit("%s: %s->lseek(): %s", __func__,
			    lastlog_file, म_त्रुटि(त्रुटि_सं));
			बंद(*fd);
			परत (0);
		}
	}

	परत (1);
}
#endif /* !LASTLOG_WRITE_PUTUTXLINE || !HAVE_GETLASTLOGXBYNAME */

#ifdef LASTLOG_WRITE_PUTUTXLINE
पूर्णांक
lastlog_write_entry(संरचना logininfo *li)
{
	निवड(li->type) {
	स्थिती LTYPE_LOGIN:
		परत 1; /* lastlog written by pututxline */
	पूर्वनिर्धारित:
		logit("lastlog_write_entry: Invalid type field");
		परत 0;
	}
}
#अन्यथा /* LASTLOG_WRITE_PUTUTXLINE */
पूर्णांक
lastlog_write_entry(संरचना logininfo *li)
{
	संरचना lastlog last;
	पूर्णांक fd;

	निवड(li->type) {
	स्थिती LTYPE_LOGIN:
		/* create our struct lastlog */
		स_रखो(&last, '\0', आकार(last));
		ओळ_stripname(last.ll_ओळ, li->ओळ, आकार(last.ll_ओळ));
		strlcpy(last.ll_host, li->hostname,
		    MIN_SIZEOF(last.ll_host, li->hostname));
		last.ll_time = li->tv_sec;

		जर (!lastlog_openseek(li, &fd, O_RDWR|O_CREAT))
			परत (0);

		/* write the entry */
		जर (atomicio(vwrite, fd, &last, आकार(last)) != आकार(last)) {
			बंद(fd);
			logit("%s: Error writing to %s: %s", __func__,
			    LASTLOG_FILE, म_त्रुटि(त्रुटि_सं));
			परत (0);
		}

		बंद(fd);
		परत (1);
	पूर्वनिर्धारित:
		logit_f("Invalid type field");
		परत (0);
	}
}
#endif /* LASTLOG_WRITE_PUTUTXLINE */

#ifdef HAVE_GETLASTLOGXBYNAME
पूर्णांक
lastlog_get_entry(संरचना logininfo *li)
{
	संरचना lastlogx l, *ll;

	जर ((ll = getlastlogxbyname(li->username, &l)) == रिक्त) {
		स_रखो(&l, '\0', आकार(l));
		ll = &l;
	}
	ओळ_fullname(li->ओळ, ll->ll_ओळ, आकार(li->ओळ));
	strlcpy(li->hostname, ll->ll_host,
		MIN_SIZEOF(li->hostname, ll->ll_host));
	li->tv_sec = ll->ll_tv.tv_sec;
	li->tv_usec = ll->ll_tv.tv_usec;
	परत (1);
}
#अन्यथा /* HAVE_GETLASTLOGXBYNAME */
पूर्णांक
lastlog_get_entry(संरचना logininfo *li)
{
	संरचना lastlog last;
	पूर्णांक fd, ret;

	जर (!lastlog_openseek(li, &fd, O_RDONLY))
		परत (0);

	ret = atomicio(पठ, fd, &last, आकार(last));
	बंद(fd);

	निवड (ret) {
	स्थिती 0:
		स_रखो(&last, '\0', आकार(last));
		/* FALLTHRU */
	स्थिती आकार(last):
		ओळ_fullname(li->ओळ, last.ll_ओळ, आकार(li->ओळ));
		strlcpy(li->hostname, last.ll_host,
		    MIN_SIZEOF(li->hostname, last.ll_host));
		li->tv_sec = last.ll_time;
		परत (1);
	स्थिती -1:
		error("%s: Error reading from %s: %s", __func__,
		    LASTLOG_FILE, म_त्रुटि(त्रुटि_सं));
		परत (0);
	पूर्वनिर्धारित:
		error("%s: Error reading from %s: Expecting %d, got %d",
		    __func__, LASTLOG_FILE, (पूर्णांक)आकार(last), ret);
		परत (0);
	}

	/* NOTREACHED */
	परत (0);
}
#endif /* HAVE_GETLASTLOGXBYNAME */
#endif /* USE_LASTLOG */

#जर defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
पूर्णांक
utmpx_get_entry(संरचना logininfo *li)
{
	संरचना utmpx *utx;

	जर (setutxdb(UTXDB_LASTLOGIN, रिक्त) != 0)
		परत (0);
	utx = getutxuser(li->username);
	जर (utx == रिक्त) {
		endutxent();
		परत (0);
	}

	ओळ_fullname(li->ओळ, utx->ut_ओळ,
	    MIN_SIZEOF(li->ओळ, utx->ut_ओळ));
	strlcpy(li->hostname, utx->ut_host,
	    MIN_SIZEOF(li->hostname, utx->ut_host));
	li->tv_sec = utx->ut_tv.tv_sec;
	li->tv_usec = utx->ut_tv.tv_usec;
	endutxent();
	परत (1);
}
#endif /* USE_UTMPX && HAVE_SETUTXDB && UTXDB_LASTLOGIN && HAVE_GETUTXUSER */

#ifdef USE_BTMP
/*
 * Logs failed login attempts in _PATH_BTMP if that exists.
 * The most common login failure is to give password instead of username.
 * So the _PATH_BTMP file is checked for the correct permission, so that only
 * root can read it.
 */
शून्य
record_failed_login(संरचना ssh *ssh, स्थिरांक अक्षर *username, स्थिरांक अक्षर *hostname,
    स्थिरांक अक्षर *ttyn)
{
	पूर्णांक fd;
	संरचना utmp ut;
	संरचना logininfo li;
	socklen_t fromlen = आकार(li.hostaddr);
	समय_प्रकार t;
	संरचना stat fst;

	जर (geteuid() != 0)
		परत;
	जर ((fd = खोलो(_PATH_BTMP, O_WRONLY | O_APPEND)) < 0) {
		debug("Unable to open the btmp file %s: %s", _PATH_BTMP,
		    म_त्रुटि(त्रुटि_सं));
		परत;
	}
	जर (ख_स्थिति(fd, &fst) < 0) {
		logit("%s: fstat of %s failed: %s", __func__, _PATH_BTMP,
		    म_त्रुटि(त्रुटि_सं));
		जा out;
	}
	जर ((fst.st_mode & (S_IXGRP | S_IRWXO)) || fst.st_uid != 0) {
		logit("Excess permission or bad ownership on file %s",
		    _PATH_BTMP);
		जा out;
	}

	/* Construct a logininfo and turn it into a utmp */
	स_रखो(&li, 0, आकार(li));
	li.type = LTYPE_FAILED;
	li.pid = getpid();
	strlcpy(li.ओळ, "ssh:notty", आकार(li.ओळ));
	strlcpy(li.username, username, आकार(li.username));
	strlcpy(li.hostname, hostname, आकार(li.hostname));
	समय(&t);
	li.tv_sec = t > 0 ? (अचिन्हित दीर्घ)t : 0;
	जर (ssh_packet_connection_is_on_socket(ssh)) {
		(शून्य)getpeername(ssh_packet_get_connection_in(ssh),
		    &li.hostaddr.sa, &fromlen);
	}
	construct_utmp(&li, &ut);

	जर (atomicio(vwrite, fd, &ut, आकार(ut)) != आकार(ut)) {
		error("Failed to write to %s: %s", _PATH_BTMP,
		    म_त्रुटि(त्रुटि_सं));
	}
out:
	बंद(fd);
}
#endif	/* USE_BTMP */
