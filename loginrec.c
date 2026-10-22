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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>
#समावेश <sys/socket.h>
#समावेश <sys/time.h>

#समावेश <netinet/in.h>

#समावेश <stdlib.h>
#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <paths.h>
#समावेश <pwd.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <time.h>
#समावेश <unistd.h>

#समावेश "xmalloc.h"
#समावेश "sshkey.h"
#समावेश "hostfile.h"
#समावेश "ssh.h"
#समावेश "loginrec.h"
#समावेश "log.h"
#समावेश "atomicio.h"
#समावेश "packet.h"
#समावेश "canohost.h"
#समावेश "auth.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "misc.h"

# include <util.h>

#अगर_घोषित USE_WTMPDB
# include <wtmpdb.h>
#पूर्ण_अगर

/**
 ** prototypes for helper functions in this file
 **/

#अगर HAVE_UTMP_H
व्योम set_utmp_time(काष्ठा logininfo *li, काष्ठा utmp *ut);
व्योम construct_utmp(काष्ठा logininfo *li, काष्ठा utmp *ut);
#पूर्ण_अगर

#अगर_घोषित HAVE_UTMPX_H
व्योम set_utmpx_time(काष्ठा logininfo *li, काष्ठा utmpx *ut);
व्योम construct_utmpx(काष्ठा logininfo *li, काष्ठा utmpx *ut);
#पूर्ण_अगर

पूर्णांक utmp_write_entry(काष्ठा logininfo *li);
पूर्णांक utmpx_write_entry(काष्ठा logininfo *li);
पूर्णांक wtmp_write_entry(काष्ठा logininfo *li);
पूर्णांक wtmpx_write_entry(काष्ठा logininfo *li);
पूर्णांक lastlog_write_entry(काष्ठा logininfo *li);
पूर्णांक syslogin_write_entry(काष्ठा logininfo *li);
#अगर_घोषित USE_WTMPDB
पूर्णांक wtmpdb_write_entry(काष्ठा logininfo *li);
#पूर्ण_अगर

पूर्णांक getlast_entry(काष्ठा logininfo *li);
पूर्णांक lastlog_get_entry(काष्ठा logininfo *li);
पूर्णांक utmpx_get_entry(काष्ठा logininfo *li);
पूर्णांक wtmp_get_entry(काष्ठा logininfo *li);
पूर्णांक wtmpx_get_entry(काष्ठा logininfo *li);

बाह्य काष्ठा sshbuf *loginmsg;

/* pick the shortest string */
#घोषणा MIN_SIZEOF(s1,s2) (माप(s1) < माप(s2) ? माप(s1) : माप(s2))

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
login_login(काष्ठा logininfo *li)
{
	li->type = LTYPE_LOGIN;
	वापस (login_write(li));
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
login_logout(काष्ठा logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	वापस (login_write(li));
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
login_get_lastlog_time(स्थिर uid_t uid)
{
	काष्ठा logininfo li;

	अगर (login_get_lastlog(&li, uid))
		वापस (li.tv_sec);
	अन्यथा
		वापस (0);
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
काष्ठा logininfo *
login_get_lastlog(काष्ठा logininfo *li, स्थिर uid_t uid)
{
	काष्ठा passwd *pw;

	स_रखो(li, '\0', माप(*li));
	li->uid = uid;

	/*
	 * If we don't have a 'real' lastlog, we need the username to
	 * reliably search wtmp(x) for the last login (see
	 * wtmp_get_entry().)
	 */
	pw = getpwuid(uid);
	अगर (pw == शून्य)
		fatal("%s: Cannot find account for uid %ld", __func__,
		    (दीर्घ)uid);

	अगर (strlcpy(li->username, pw->pw_name, माप(li->username)) >=
	    माप(li->username)) {
		error("%s: username too long (%lu > max %lu)", __func__,
		    (अचिन्हित दीर्घ)म_माप(pw->pw_name),
		    (अचिन्हित दीर्घ)माप(li->username) - 1);
		वापस शून्य;
	}

	अगर (getlast_entry(li))
		वापस (li);
	अन्यथा
		वापस (शून्य);
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
काष्ठा
logininfo *login_alloc_entry(pid_t pid, स्थिर अक्षर *username,
    स्थिर अक्षर *hostname, स्थिर अक्षर *पंक्ति)
{
	काष्ठा logininfo *newli;

	newli = xmalloc(माप(*newli));
	login_init_entry(newli, pid, username, hostname, पंक्ति);
	वापस (newli);
}


/* login_free_entry(struct logininfo *)    - free struct memory */
व्योम
login_free_entry(काष्ठा logininfo *li)
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
login_init_entry(काष्ठा logininfo *li, pid_t pid, स्थिर अक्षर *username,
    स्थिर अक्षर *hostname, स्थिर अक्षर *पंक्ति)
{
	काष्ठा passwd *pw;

	स_रखो(li, 0, माप(*li));

	li->pid = pid;

	/* set the line information */
	अगर (पंक्ति)
		पंक्ति_fullname(li->पंक्ति, पंक्ति, माप(li->पंक्ति));

	अगर (username) {
		strlcpy(li->username, username, माप(li->username));
		pw = getpwnam(li->username);
		अगर (pw == शून्य) {
			fatal("%s: Cannot find user \"%s\"", __func__,
			    li->username);
		}
		li->uid = pw->pw_uid;
	}

	अगर (hostname)
		strlcpy(li->hostname, hostname, माप(li->hostname));

	वापस (1);
}

/*
 * login_set_current_time(struct logininfo *)    - set the current time
 *
 * Set the current time in a logininfo structure. This function is
 * meant to eliminate the need to deal with system dependencies for
 * time handling.
 */
व्योम
login_set_current_time(काष्ठा logininfo *li)
{
	काष्ठा timeval tv;

	gettimeofday(&tv, शून्य);

	li->tv_sec = tv.tv_sec;
	li->tv_usec = tv.tv_usec;
}

/* copy a sockaddr_* into our logininfo */
व्योम
login_set_addr(काष्ठा logininfo *li, स्थिर काष्ठा sockaddr *sa,
    स्थिर अचिन्हित पूर्णांक sa_आकार)
{
	अचिन्हित पूर्णांक bufsize = sa_आकार;

	/* make sure we don't overrun our union */
	अगर (माप(li->hostaddr) < sa_आकार)
		bufsize = माप(li->hostaddr);

	स_नकल(&li->hostaddr.sa, sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/
पूर्णांक
login_write(काष्ठा logininfo *li)
{
#अगर_अघोषित HAVE_CYGWIN
	अगर (geteuid() != 0) {
		logit("Attempt to write login records by non-root user (aborting)");
		वापस (1);
	}
#पूर्ण_अगर

	/* set the timestamp */
	login_set_current_time(li);
#अगर_घोषित USE_LOGIN
	syslogin_write_entry(li);
#पूर्ण_अगर
#अगर_घोषित USE_LASTLOG
	अगर (li->type == LTYPE_LOGIN)
		lastlog_write_entry(li);
#पूर्ण_अगर
#अगर_घोषित USE_UTMP
	utmp_write_entry(li);
#पूर्ण_अगर
#अगर_घोषित USE_WTMP
	wtmp_write_entry(li);
#पूर्ण_अगर
#अगर_घोषित USE_UTMPX
	utmpx_write_entry(li);
#पूर्ण_अगर
#अगर_घोषित USE_WTMPX
	wtmpx_write_entry(li);
#पूर्ण_अगर
#अगर_घोषित USE_WTMPDB
	wtmpdb_write_entry(li);
#पूर्ण_अगर
#अगर_घोषित CUSTOM_SYS_AUTH_RECORD_LOGIN
	अगर (li->type == LTYPE_LOGIN &&
	    !sys_auth_record_login(li->username,li->hostname,li->पंक्ति,
	    loginmsg))
		logit("Writing login record failed for %s", li->username);
#पूर्ण_अगर
#अगर_घोषित SSH_AUDIT_EVENTS
	अगर (li->type == LTYPE_LOGIN)
		audit_session_open(li);
	अन्यथा अगर (li->type == LTYPE_LOGOUT)
		audit_session_close(li);
#पूर्ण_अगर
	वापस (0);
}

#अगर_घोषित LOGIN_NEEDS_UTMPX
पूर्णांक
login_utmp_only(काष्ठा logininfo *li)
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
	वापस (0);
}
#पूर्ण_अगर

/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
पूर्णांक
getlast_entry(काष्ठा logininfo *li)
{
#अगर_घोषित USE_LASTLOG
	वापस(lastlog_get_entry(li));
#अन्यथा /* !USE_LASTLOG */
#अगर defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
	वापस (utmpx_get_entry(li));
#पूर्ण_अगर

#अगर defined(DISABLE_LASTLOG)
	/* On some systems we shouldn't even try to obtain last login
	 * time, e.g. AIX */
	वापस (0);
# elif defined(USE_WTMP) && \
    (defined(HAVE_TIME_IN_UTMP) || defined(HAVE_TV_IN_UTMP))
	/* retrieve last login time from utmp */
	वापस (wtmp_get_entry(li));
# elif defined(USE_WTMPX) && \
    (defined(HAVE_TIME_IN_UTMPX) || defined(HAVE_TV_IN_UTMPX))
	/* If wtmp isn't available, try wtmpx */
	वापस (wtmpx_get_entry(li));
# अन्यथा
	/* Give up: No means of retrieving last login time */
	वापस (0);
# endif /* DISABLE_LASTLOG */
#पूर्ण_अगर /* USE_LASTLOG */
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
पंक्ति_fullname(अक्षर *dst, स्थिर अक्षर *src, u_int dstsize)
{
	स_रखो(dst, '\0', dstsize);
	अगर ((म_भेदन(src, "/dev/", 5) == 0) || (dstsize < (म_माप(src) + 5)))
		strlcpy(dst, src, dstsize);
	अन्यथा {
		strlcpy(dst, "/dev/", dstsize);
		strlcat(dst, src, dstsize);
	}
	वापस (dst);
}

/* line_stripname(): strip the leading '/dev' if it exists, return dst */
अक्षर *
पंक्ति_stripname(अक्षर *dst, स्थिर अक्षर *src, पूर्णांक dstsize)
{
	स_रखो(dst, '\0', dstsize);
	अगर (म_भेदन(src, "/dev/", 5) == 0)
		strlcpy(dst, src + 5, dstsize);
	अन्यथा
		strlcpy(dst, src, dstsize);
	वापस (dst);
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
पंक्ति_abbrevname(अक्षर *dst, स्थिर अक्षर *src, पूर्णांक dstsize)
{
	माप_प्रकार len;

	स_रखो(dst, '\0', dstsize);

	अगर (म_भेद(src, "ssh:notty") == 0)
		वापस dst;

	/* Always skip prefix if present */
	अगर (म_भेदन(src, "/dev/", 5) == 0)
		src += 5;

#अगर_घोषित WITH_ABBREV_NO_TTY
	अगर (म_भेदन(src, "tty", 3) == 0)
		src += 3;
#पूर्ण_अगर

	len = म_माप(src);

	अगर (len > 0) {
		अगर (((पूर्णांक)len - dstsize) > 0)
			src +=  ((पूर्णांक)len - dstsize);

		/* note: _don't_ change this to strlcpy */
		म_नकलन(dst, src, (माप_प्रकार)dstsize);
	}

	वापस (dst);
}

/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#अगर defined(USE_BTMP) || defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
व्योम
set_utmp_time(काष्ठा logininfo *li, काष्ठा utmp *ut)
{
# अगर defined(HAVE_TV_IN_UTMP)
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMP)
	ut->ut_time = li->tv_sec;
# endif
}

व्योम
construct_utmp(काष्ठा logininfo *li,
		    काष्ठा utmp *ut)
{
# ifdef HAVE_ADDR_V6_IN_UTMP
	काष्ठा sockaddr_in6 *sa6;
# endif

	स_रखो(ut, '\0', माप(*ut));

	/* First fill out fields used for both logins and logouts */

# ifdef HAVE_ID_IN_UTMP
	पंक्ति_abbrevname(ut->ut_id, li->पंक्ति, माप(ut->ut_id));
# endif

# ifdef HAVE_TYPE_IN_UTMP
	/* This is done here to keep utmp constants out of struct logininfo */
	चयन (li->type) {
	हाल LTYPE_FAILED:
		ut->ut_type = LOGIN_PROCESS;
		अवरोध;
	हाल LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		अवरोध;
	हाल LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		अवरोध;
	}
# endif
	set_utmp_time(li, ut);

	पंक्ति_stripname(ut->ut_पंक्ति, li->पंक्ति, माप(ut->ut_पंक्ति));

# ifdef HAVE_PID_IN_UTMP
	ut->ut_pid = li->pid;
# endif

	/* If we're logging out, leave all other fields blank */
	अगर (li->type == LTYPE_LOGOUT)
		वापस;

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
	अगर (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMP
	/* this is just a 128-bit IPv6 address */
	अगर (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((काष्ठा sockaddr_in6 *)&li->hostaddr.sa);
		स_नकल(ut->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		अगर (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			ut->ut_addr_v6[0] = ut->ut_addr_v6[3];
			ut->ut_addr_v6[1] = 0;
			ut->ut_addr_v6[2] = 0;
			ut->ut_addr_v6[3] = 0;
		}
	}
# endif
}
#पूर्ण_अगर /* USE_BTMP || USE_UTMP || USE_WTMP || USE_LOGIN */

/**
 ** utmpx utility functions
 **
 ** These functions manipulate struct utmpx, accounting for system
 ** variations.
 **/

#अगर defined(USE_UTMPX) || defined (USE_WTMPX)
/* build the utmpx structure */
व्योम
set_utmpx_time(काष्ठा logininfo *li, काष्ठा utmpx *utx)
{
# अगर defined(HAVE_TV_IN_UTMPX)
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMPX)
	utx->ut_time = li->tv_sec;
# endif
}

व्योम
construct_utmpx(काष्ठा logininfo *li, काष्ठा utmpx *utx)
{
# ifdef HAVE_ADDR_V6_IN_UTMPX
	काष्ठा sockaddr_in6 *sa6;
#  endif
	स_रखो(utx, '\0', माप(*utx));

# ifdef HAVE_ID_IN_UTMPX
	पंक्ति_abbrevname(utx->ut_id, li->पंक्ति, माप(utx->ut_id));
# endif

	/* this is done here to keep utmp constants out of loginrec.h */
	चयन (li->type) {
	हाल LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		अवरोध;
	हाल LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		अवरोध;
	}
	पंक्ति_stripname(utx->ut_पंक्ति, li->पंक्ति, माप(utx->ut_पंक्ति));
	set_utmpx_time(li, utx);
	utx->ut_pid = li->pid;

	/* strncpy(): Don't necessarily want null termination */
	म_नकलन(utx->ut_user, li->username,
	    MIN_SIZEOF(utx->ut_user, li->username));

	अगर (li->type == LTYPE_LOGOUT)
		वापस;

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
	अगर (li->hostaddr.sa.sa_family == AF_INET)
		utx->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMPX
	/* this is just a 128-bit IPv6 address */
	अगर (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((काष्ठा sockaddr_in6 *)&li->hostaddr.sa);
		स_नकल(utx->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		अगर (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			utx->ut_addr_v6[0] = utx->ut_addr_v6[3];
			utx->ut_addr_v6[1] = 0;
			utx->ut_addr_v6[2] = 0;
			utx->ut_addr_v6[3] = 0;
		}
	}
# endif
# ifdef HAVE_SYSLEN_IN_UTMPX
	/* ut_syslen is the length of the utx_host string */
	utx->ut_syslen = MINIMUM(म_माप(li->hostname), माप(utx->ut_host));
# endif
}
#पूर्ण_अगर /* USE_UTMPX || USE_WTMPX */

/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */
#अगर_घोषित USE_UTMP

/* if we can, use pututline() etc. */
# अगर !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
	defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
# endif


/* write a utmp entry with the system's help (pututline() and pals) */
# ifdef UTMP_USE_LIBRARY
अटल पूर्णांक
utmp_write_library(काष्ठा logininfo *li, काष्ठा utmp *ut)
{
	setutent();
	pututline(ut);
#  ifdef HAVE_ENDUTENT
	endutent();
#  endif
	वापस (1);
}
# अन्यथा /* UTMP_USE_LIBRARY */

/*
 * Write a utmp entry direct to the file
 * This is a slightly modification of code in OpenBSD's login.c
 */
अटल पूर्णांक
utmp_write_direct(काष्ठा logininfo *li, काष्ठा utmp *ut)
{
	काष्ठा utmp old_ut;
	रेजिस्टर पूर्णांक fd;
	पूर्णांक tty;

	/* FIXME: (ATL) ttyslot() needs local implementation */

#अगर defined(HAVE_GETTTYENT)
	काष्ठा ttyent *ty;

	tty=0;
	setttyent();
	जबतक (शून्य != (ty = getttyent())) {
		tty++;
		अगर (!म_भेदन(ty->ty_name, ut->ut_पंक्ति, माप(ut->ut_पंक्ति)))
			अवरोध;
	}
	endttyent();

	अगर (शून्य == ty) {
		logit_f("tty not found");
		वापस (0);
	}
#अन्यथा /* FIXME */

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

#पूर्ण_अगर /* HAVE_GETTTYENT */

	अगर (tty > 0 && (fd = खोलो(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		off_t pos, ret;

		pos = (off_t)tty * माप(काष्ठा utmp);
		अगर ((ret = lseek(fd, pos, शुरू_से)) == -1) {
			logit_f("lseek: %s", म_त्रुटि(त्रुटि_सं));
			बंद(fd);
			वापस (0);
		}
		अगर (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			बंद(fd);
			वापस (0);
		}
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		अगर (atomicio(पढ़ो, fd, &old_ut, माप(old_ut)) == माप(old_ut) &&
		    (ut->ut_host[0] == '\0') && (old_ut.ut_host[0] != '\0') &&
		    (म_भेदन(old_ut.ut_पंक्ति, ut->ut_पंक्ति, माप(ut->ut_पंक्ति)) == 0) &&
		    (म_भेदन(old_ut.ut_name, ut->ut_name, माप(ut->ut_name)) == 0))
			स_नकल(ut->ut_host, old_ut.ut_host, माप(ut->ut_host));

		अगर ((ret = lseek(fd, pos, शुरू_से)) == -1) {
			logit_f("lseek: %s", म_त्रुटि(त्रुटि_सं));
			बंद(fd);
			वापस (0);
		}
		अगर (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			बंद(fd);
			वापस (0);
		}
		अगर (atomicio(vwrite, fd, ut, माप(*ut)) != माप(*ut)) {
			logit("%s: error writing %s: %s", __func__,
			    UTMP_FILE, म_त्रुटि(त्रुटि_सं));
			बंद(fd);
			वापस (0);
		}

		बंद(fd);
		वापस (1);
	} अन्यथा {
		वापस (0);
	}
}
# endif /* UTMP_USE_LIBRARY */

अटल पूर्णांक
utmp_perform_login(काष्ठा logininfo *li)
{
	काष्ठा utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	अगर (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		वापस (0);
	}
# अन्यथा
	अगर (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		वापस (0);
	}
# endif
	वापस (1);
}


अटल पूर्णांक
utmp_perform_logout(काष्ठा logininfo *li)
{
	काष्ठा utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	अगर (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		वापस (0);
	}
# अन्यथा
	अगर (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		वापस (0);
	}
# endif
	वापस (1);
}


पूर्णांक
utmp_write_entry(काष्ठा logininfo *li)
{
	चयन(li->type) {
	हाल LTYPE_LOGIN:
		वापस (utmp_perform_login(li));

	हाल LTYPE_LOGOUT:
		वापस (utmp_perform_logout(li));

	शेष:
		logit_f("invalid type field");
		वापस (0);
	}
}
#पूर्ण_अगर /* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#अगर_घोषित USE_UTMPX

/* if we have the wherewithal, use pututxline etc. */
# अगर !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) && \
	defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
# endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
# ifdef UTMPX_USE_LIBRARY
अटल पूर्णांक
utmpx_write_library(काष्ठा logininfo *li, काष्ठा utmpx *utx)
{
	setutxent();
	pututxline(utx);

#  ifdef HAVE_ENDUTXENT
	endutxent();
#  endif
	वापस (1);
}

# अन्यथा /* UTMPX_USE_LIBRARY */

/* write a utmp entry direct to the file */
अटल पूर्णांक
utmpx_write_direct(काष्ठा logininfo *li, काष्ठा utmpx *utx)
{
	logit_f("not implemented!");
	वापस (0);
}
# endif /* UTMPX_USE_LIBRARY */

अटल पूर्णांक
utmpx_perform_login(काष्ठा logininfo *li)
{
	काष्ठा utmpx utx;

	construct_utmpx(li, &utx);
# ifdef UTMPX_USE_LIBRARY
	अगर (!utmpx_write_library(li, &utx)) {
		logit_f("utmp_write_library() failed");
		वापस (0);
	}
# अन्यथा
	अगर (!utmpx_write_direct(li, &utx)) {
		logit_f("utmp_write_direct() failed");
		वापस (0);
	}
# endif
	वापस (1);
}


अटल पूर्णांक
utmpx_perform_logout(काष्ठा logininfo *li)
{
	काष्ठा utmpx utx;

	construct_utmpx(li, &utx);
# ifdef HAVE_ID_IN_UTMPX
	पंक्ति_abbrevname(utx.ut_id, li->पंक्ति, माप(utx.ut_id));
# endif
# ifdef HAVE_TYPE_IN_UTMPX
	utx.ut_type = DEAD_PROCESS;
# endif

# ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
# अन्यथा
	utmpx_write_direct(li, &utx);
# endif
	वापस (1);
}

पूर्णांक
utmpx_write_entry(काष्ठा logininfo *li)
{
	चयन(li->type) {
	हाल LTYPE_LOGIN:
		वापस (utmpx_perform_login(li));
	हाल LTYPE_LOGOUT:
		वापस (utmpx_perform_logout(li));
	शेष:
		logit_f("invalid type field");
		वापस (0);
	}
}
#पूर्ण_अगर /* USE_UTMPX */


/**
 ** Low-level wtmp functions
 **/

#अगर_घोषित USE_WTMP

/*
 * Write a wtmp entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
अटल पूर्णांक
wtmp_write(काष्ठा logininfo *li, काष्ठा utmp *ut)
{
	काष्ठा stat buf;
	पूर्णांक fd, ret = 1;

	अगर ((fd = खोलो(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem writing %s: %s", __func__,
		    WTMP_FILE, म_त्रुटि(त्रुटि_सं));
		वापस (0);
	}
	अगर (ख_स्थिति(fd, &buf) == 0)
		अगर (atomicio(vwrite, fd, ut, माप(*ut)) != माप(*ut)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMP_FILE, म_त्रुटि(त्रुटि_सं));
			ret = 0;
		}
	बंद(fd);
	वापस (ret);
}

अटल पूर्णांक
wtmp_perform_login(काष्ठा logininfo *li)
{
	काष्ठा utmp ut;

	construct_utmp(li, &ut);
	वापस (wtmp_write(li, &ut));
}


अटल पूर्णांक
wtmp_perform_logout(काष्ठा logininfo *li)
{
	काष्ठा utmp ut;

	construct_utmp(li, &ut);
	वापस (wtmp_write(li, &ut));
}


पूर्णांक
wtmp_write_entry(काष्ठा logininfo *li)
{
	चयन(li->type) {
	हाल LTYPE_LOGIN:
		वापस (wtmp_perform_login(li));
	हाल LTYPE_LOGOUT:
		वापस (wtmp_perform_logout(li));
	शेष:
		logit_f("invalid type field");
		वापस (0);
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
अटल पूर्णांक
wtmp_islogin(काष्ठा logininfo *li, काष्ठा utmp *ut)
{
	अगर (म_भेदन(li->username, ut->ut_name,
	    MIN_SIZEOF(li->username, ut->ut_name)) == 0) {
# ifdef HAVE_TYPE_IN_UTMP
		अगर (ut->ut_type & USER_PROCESS)
			वापस (1);
# अन्यथा
		वापस (1);
# endif
	}
	वापस (0);
}

पूर्णांक
wtmp_get_entry(काष्ठा logininfo *li)
{
	काष्ठा stat st;
	काष्ठा utmp ut;
	पूर्णांक fd, found = 0;

	/* Clear the time entries in our logininfo */
	li->tv_sec = li->tv_usec = 0;

	अगर ((fd = खोलो(WTMP_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMP_FILE, म_त्रुटि(त्रुटि_सं));
		वापस (0);
	}
	अगर (ख_स्थिति(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMP_FILE, म_त्रुटि(त्रुटि_सं));
		बंद(fd);
		वापस (0);
	}

	/* Seek to the start of the last struct utmp */
	अगर (lseek(fd, -(off_t)माप(काष्ठा utmp), अंत_से) == -1) {
		/* Looks like we've got a fresh wtmp file */
		बंद(fd);
		वापस (0);
	}

	जबतक (!found) {
		अगर (atomicio(पढ़ो, fd, &ut, माप(ut)) != माप(ut)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMP_FILE, म_त्रुटि(त्रुटि_सं));
			बंद (fd);
			वापस (0);
		}
		अगर (wtmp_islogin(li, &ut) ) {
			found = 1;
			/*
			 * We've already checked for a time in struct
			 * utmp, in login_getlast()
			 */
# ifdef HAVE_TIME_IN_UTMP
			li->tv_sec = ut.ut_time;
# अन्यथा
#  अगर HAVE_TV_IN_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
# endif
			पंक्ति_fullname(li->पंक्ति, ut.ut_पंक्ति,
			    MIN_SIZEOF(li->पंक्ति, ut.ut_पंक्ति));
# ifdef HAVE_HOST_IN_UTMP
			strlcpy(li->hostname, ut.ut_host,
			    MIN_SIZEOF(li->hostname, ut.ut_host));
# endif
			जारी;
		}
		/* Seek back 2 x struct utmp */
		अगर (lseek(fd, -(off_t)(2 * माप(काष्ठा utmp)), प्रस्तुत_से) == -1) {
			/* We've found the start of the file, so quit */
			बंद(fd);
			वापस (0);
		}
	}

	/* We found an entry. Tidy up and return */
	बंद(fd);
	वापस (1);
}
# endif /* USE_WTMP */


/**
 ** Low-level wtmpx functions
 **/

#अगर_घोषित USE_WTMPX
/*
 * Write a wtmpx entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
अटल पूर्णांक
wtmpx_write(काष्ठा logininfo *li, काष्ठा utmpx *utx)
{
#अगर_अघोषित HAVE_UPDWTMPX
	काष्ठा stat buf;
	पूर्णांक fd, ret = 1;

	अगर ((fd = खोलो(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, म_त्रुटि(त्रुटि_सं));
		वापस (0);
	}

	अगर (ख_स्थिति(fd, &buf) == 0)
		अगर (atomicio(vwrite, fd, utx, माप(*utx)) != माप(*utx)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMPX_FILE, म_त्रुटि(त्रुटि_सं));
			ret = 0;
		}
	बंद(fd);

	वापस (ret);
#अन्यथा
	updwtmpx(WTMPX_FILE, utx);
	वापस (1);
#पूर्ण_अगर
}


अटल पूर्णांक
wtmpx_perform_login(काष्ठा logininfo *li)
{
	काष्ठा utmpx utx;

	construct_utmpx(li, &utx);
	वापस (wtmpx_write(li, &utx));
}


अटल पूर्णांक
wtmpx_perform_logout(काष्ठा logininfo *li)
{
	काष्ठा utmpx utx;

	construct_utmpx(li, &utx);
	वापस (wtmpx_write(li, &utx));
}


पूर्णांक
wtmpx_write_entry(काष्ठा logininfo *li)
{
	चयन(li->type) {
	हाल LTYPE_LOGIN:
		वापस (wtmpx_perform_login(li));
	हाल LTYPE_LOGOUT:
		वापस (wtmpx_perform_logout(li));
	शेष:
		logit_f("invalid type field");
		वापस (0);
	}
}

/* Please see the notes above wtmp_islogin() for information about the
   next two functions */

/* Return true if this wtmpx entry indicates a login */
अटल पूर्णांक
wtmpx_islogin(काष्ठा logininfo *li, काष्ठा utmpx *utx)
{
	अगर (म_भेदन(li->username, utx->ut_user,
	    MIN_SIZEOF(li->username, utx->ut_user)) == 0 ) {
# ifdef HAVE_TYPE_IN_UTMPX
		अगर (utx->ut_type == USER_PROCESS)
			वापस (1);
# अन्यथा
		वापस (1);
# endif
	}
	वापस (0);
}


पूर्णांक
wtmpx_get_entry(काष्ठा logininfo *li)
{
	काष्ठा stat st;
	काष्ठा utmpx utx;
	पूर्णांक fd, found=0;

	/* Clear the time entries */
	li->tv_sec = li->tv_usec = 0;

	अगर ((fd = खोलो(WTMPX_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, म_त्रुटि(त्रुटि_सं));
		वापस (0);
	}
	अगर (ख_स्थिति(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMPX_FILE, म_त्रुटि(त्रुटि_सं));
		बंद(fd);
		वापस (0);
	}

	/* Seek to the start of the last struct utmpx */
	अगर (lseek(fd, -(off_t)माप(काष्ठा utmpx), अंत_से) == -1 ) {
		/* probably a newly rotated wtmpx file */
		बंद(fd);
		वापस (0);
	}

	जबतक (!found) {
		अगर (atomicio(पढ़ो, fd, &utx, माप(utx)) != माप(utx)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMPX_FILE, म_त्रुटि(त्रुटि_सं));
			बंद (fd);
			वापस (0);
		}
		/*
		 * Logouts are recorded as a blank username on a particular
		 * line. So, we just need to find the username in struct utmpx
		 */
		अगर (wtmpx_islogin(li, &utx)) {
			found = 1;
# अगर defined(HAVE_TV_IN_UTMPX)
			li->tv_sec = utx.ut_tv.tv_sec;
# elif defined(HAVE_TIME_IN_UTMPX)
			li->tv_sec = utx.ut_time;
# endif
			पंक्ति_fullname(li->पंक्ति, utx.ut_पंक्ति, माप(li->पंक्ति));
# अगर defined(HAVE_HOST_IN_UTMPX)
			strlcpy(li->hostname, utx.ut_host,
			    MIN_SIZEOF(li->hostname, utx.ut_host));
# endif
			जारी;
		}
		अगर (lseek(fd, -(off_t)(2 * माप(काष्ठा utmpx)), प्रस्तुत_से) == -1) {
			बंद(fd);
			वापस (0);
		}
	}

	बंद(fd);
	वापस (1);
}
#पूर्ण_अगर /* USE_WTMPX */

#अगर_घोषित USE_WTMPDB
अटल पूर्णांक
wtmpdb_perform_login(काष्ठा logininfo *li)
{
	uint64_t login_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	    li->tv_usec;
	स्थिर अक्षर *tty;

	अगर (म_भेदन(li->पंक्ति, "/dev/", 5) == 0)
		tty = &(li->पंक्ति[5]);
	अन्यथा
		tty = li->पंक्ति;

	li->wtmpdb_id = wtmpdb_login(शून्य, USER_PROCESS, li->username,
	    login_time, tty, li->hostname, 0, 0);

	अगर (li->wtmpdb_id < 0)
		वापस (0);

	वापस (1);
}

अटल पूर्णांक
wtmpdb_perform_logout(काष्ठा logininfo *li)
{
	uint64_t logout_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	   li->tv_usec;

	अगर (li->wtmpdb_id == 0) {
		स्थिर अक्षर *tty;

		अगर (म_भेदन(li->पंक्ति, "/dev/", 5) == 0)
			tty = &(li->पंक्ति[5]);
		अन्यथा
			tty = li->पंक्ति;

		li->wtmpdb_id = wtmpdb_get_id(शून्य, tty, शून्य);
	}
	wtmpdb_logout(शून्य, li->wtmpdb_id, logout_time, शून्य);

	वापस (1);
}

पूर्णांक
wtmpdb_write_entry(काष्ठा logininfo *li)
{
	चयन(li->type) {
	हाल LTYPE_LOGIN:
		वापस (wtmpdb_perform_login(li));
	हाल LTYPE_LOGOUT:
		वापस (wtmpdb_perform_logout(li));
	शेष:
		logit_f("invalid type field");
		वापस (0);
	}
}
#पूर्ण_अगर

/**
 ** Low-level libutil login() functions
 **/

#अगर_घोषित USE_LOGIN
अटल पूर्णांक
syslogin_perform_login(काष्ठा logininfo *li)
{
	काष्ठा utmp *ut;

	ut = xmalloc(माप(*ut));
	construct_utmp(li, ut);
	login(ut);
	मुक्त(ut);

	वापस (1);
}

अटल पूर्णांक
syslogin_perform_logout(काष्ठा logininfo *li)
{
# ifdef HAVE_LOGOUT
	अक्षर पंक्ति[UT_LINESIZE];

	(व्योम)पंक्ति_stripname(पंक्ति, li->पंक्ति, माप(पंक्ति));

	अगर (!logout(पंक्ति))
		logit_f("logout() returned an error");
#  ifdef HAVE_LOGWTMP
	अन्यथा
		logwtmp(पंक्ति, "", "");
#  endif
	/* FIXME: (ATL - if the need arises) What to do if we have
	 * login, but no logout?  what if logout but no logwtmp? All
	 * routines are in libutil so they should all be there,
	 * but... */
# endif
	वापस (1);
}

पूर्णांक
syslogin_write_entry(काष्ठा logininfo *li)
{
	चयन (li->type) {
	हाल LTYPE_LOGIN:
		वापस (syslogin_perform_login(li));
	हाल LTYPE_LOGOUT:
		वापस (syslogin_perform_logout(li));
	शेष:
		logit_f("Invalid type field");
		वापस (0);
	}
}
#पूर्ण_अगर /* USE_LOGIN */

/* end of file log-syslogin.c */

/**
 ** Low-level lastlog functions
 **/

#अगर_घोषित USE_LASTLOG

#अगर !defined(LASTLOG_WRITE_PUTUTXLINE) || !defined(HAVE_GETLASTLOGXBYNAME)
/* open the file (using filemode) and seek to the login entry */
अटल पूर्णांक
lastlog_openseek(काष्ठा logininfo *li, पूर्णांक *fd, पूर्णांक filemode)
{
	off_t offset;
	अक्षर lastlog_file[1024];
	काष्ठा stat st;

	अगर (stat(LASTLOG_FILE, &st) != 0) {
		logit("%s: Couldn't stat %s: %s", __func__,
		    LASTLOG_FILE, म_त्रुटि(त्रुटि_सं));
		वापस (0);
	}
	अगर (S_ISDIR(st.st_mode)) {
		snprintf(lastlog_file, माप(lastlog_file), "%s/%s",
		    LASTLOG_FILE, li->username);
	} अन्यथा अगर (S_ISREG(st.st_mode)) {
		strlcpy(lastlog_file, LASTLOG_FILE, माप(lastlog_file));
	} अन्यथा {
		logit("%s: %.100s is not a file or directory!", __func__,
		    LASTLOG_FILE);
		वापस (0);
	}

	*fd = खोलो(lastlog_file, filemode, 0600);
	अगर (*fd < 0) {
		debug("%s: Couldn't open %s: %s", __func__,
		    lastlog_file, म_त्रुटि(त्रुटि_सं));
		वापस (0);
	}

	अगर (S_ISREG(st.st_mode)) {
		/* find this uid's offset in the lastlog file */
		offset = (off_t) ((u_long)li->uid * माप(काष्ठा lastlog));

		अगर (lseek(*fd, offset, शुरू_से) != offset) {
			logit("%s: %s->lseek(): %s", __func__,
			    lastlog_file, म_त्रुटि(त्रुटि_सं));
			बंद(*fd);
			वापस (0);
		}
	}

	वापस (1);
}
#पूर्ण_अगर /* !LASTLOG_WRITE_PUTUTXLINE || !HAVE_GETLASTLOGXBYNAME */

#अगर_घोषित LASTLOG_WRITE_PUTUTXLINE
पूर्णांक
lastlog_write_entry(काष्ठा logininfo *li)
{
	चयन(li->type) {
	हाल LTYPE_LOGIN:
		वापस 1; /* lastlog written by pututxline */
	शेष:
		logit("lastlog_write_entry: Invalid type field");
		वापस 0;
	}
}
#अन्यथा /* LASTLOG_WRITE_PUTUTXLINE */
पूर्णांक
lastlog_write_entry(काष्ठा logininfo *li)
{
	काष्ठा lastlog last;
	पूर्णांक fd;

	चयन(li->type) {
	हाल LTYPE_LOGIN:
		/* create our struct lastlog */
		स_रखो(&last, '\0', माप(last));
		पंक्ति_stripname(last.ll_पंक्ति, li->पंक्ति, माप(last.ll_पंक्ति));
		strlcpy(last.ll_host, li->hostname,
		    MIN_SIZEOF(last.ll_host, li->hostname));
		last.ll_time = li->tv_sec;

		अगर (!lastlog_openseek(li, &fd, O_RDWR|O_CREAT))
			वापस (0);

		/* write the entry */
		अगर (atomicio(vwrite, fd, &last, माप(last)) != माप(last)) {
			बंद(fd);
			logit("%s: Error writing to %s: %s", __func__,
			    LASTLOG_FILE, म_त्रुटि(त्रुटि_सं));
			वापस (0);
		}

		बंद(fd);
		वापस (1);
	शेष:
		logit_f("Invalid type field");
		वापस (0);
	}
}
#पूर्ण_अगर /* LASTLOG_WRITE_PUTUTXLINE */

#अगर_घोषित HAVE_GETLASTLOGXBYNAME
पूर्णांक
lastlog_get_entry(काष्ठा logininfo *li)
{
	काष्ठा lastlogx l, *ll;

	अगर ((ll = getlastlogxbyname(li->username, &l)) == शून्य) {
		स_रखो(&l, '\0', माप(l));
		ll = &l;
	}
	पंक्ति_fullname(li->पंक्ति, ll->ll_पंक्ति, माप(li->पंक्ति));
	strlcpy(li->hostname, ll->ll_host,
		MIN_SIZEOF(li->hostname, ll->ll_host));
	li->tv_sec = ll->ll_tv.tv_sec;
	li->tv_usec = ll->ll_tv.tv_usec;
	वापस (1);
}
#अन्यथा /* HAVE_GETLASTLOGXBYNAME */
पूर्णांक
lastlog_get_entry(काष्ठा logininfo *li)
{
	काष्ठा lastlog last;
	पूर्णांक fd, ret;

	अगर (!lastlog_openseek(li, &fd, O_RDONLY))
		वापस (0);

	ret = atomicio(पढ़ो, fd, &last, माप(last));
	बंद(fd);

	चयन (ret) {
	हाल 0:
		स_रखो(&last, '\0', माप(last));
		/* FALLTHRU */
	हाल माप(last):
		पंक्ति_fullname(li->पंक्ति, last.ll_पंक्ति, माप(li->पंक्ति));
		strlcpy(li->hostname, last.ll_host,
		    MIN_SIZEOF(li->hostname, last.ll_host));
		li->tv_sec = last.ll_time;
		वापस (1);
	हाल -1:
		error("%s: Error reading from %s: %s", __func__,
		    LASTLOG_FILE, म_त्रुटि(त्रुटि_सं));
		वापस (0);
	शेष:
		error("%s: Error reading from %s: Expecting %d, got %d",
		    __func__, LASTLOG_FILE, (पूर्णांक)माप(last), ret);
		वापस (0);
	}

	/* NOTREACHED */
	वापस (0);
}
#पूर्ण_अगर /* HAVE_GETLASTLOGXBYNAME */
#पूर्ण_अगर /* USE_LASTLOG */

#अगर defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
पूर्णांक
utmpx_get_entry(काष्ठा logininfo *li)
{
	काष्ठा utmpx *utx;

	अगर (setutxdb(UTXDB_LASTLOGIN, शून्य) != 0)
		वापस (0);
	utx = getutxuser(li->username);
	अगर (utx == शून्य) {
		endutxent();
		वापस (0);
	}

	पंक्ति_fullname(li->पंक्ति, utx->ut_पंक्ति,
	    MIN_SIZEOF(li->पंक्ति, utx->ut_पंक्ति));
	strlcpy(li->hostname, utx->ut_host,
	    MIN_SIZEOF(li->hostname, utx->ut_host));
	li->tv_sec = utx->ut_tv.tv_sec;
	li->tv_usec = utx->ut_tv.tv_usec;
	endutxent();
	वापस (1);
}
#पूर्ण_अगर /* USE_UTMPX && HAVE_SETUTXDB && UTXDB_LASTLOGIN && HAVE_GETUTXUSER */

#अगर_घोषित USE_BTMP
/*
 * Logs failed login attempts in _PATH_BTMP if that exists.
 * The most common login failure is to give password instead of username.
 * So the _PATH_BTMP file is checked for the correct permission, so that only
 * root can read it.
 */
व्योम
record_failed_login(काष्ठा ssh *ssh, स्थिर अक्षर *username, स्थिर अक्षर *hostname,
    स्थिर अक्षर *ttyn)
{
	पूर्णांक fd;
	काष्ठा utmp ut;
	काष्ठा logininfo li;
	socklen_t fromlen = माप(li.hostaddr);
	समय_प्रकार t;
	काष्ठा stat fst;

	अगर (geteuid() != 0)
		वापस;
	अगर ((fd = खोलो(_PATH_BTMP, O_WRONLY | O_APPEND)) < 0) {
		debug("Unable to open the btmp file %s: %s", _PATH_BTMP,
		    म_त्रुटि(त्रुटि_सं));
		वापस;
	}
	अगर (ख_स्थिति(fd, &fst) < 0) {
		logit("%s: fstat of %s failed: %s", __func__, _PATH_BTMP,
		    म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	अगर ((fst.st_mode & (S_IXGRP | S_IRWXO)) || fst.st_uid != 0) {
		logit("Excess permission or bad ownership on file %s",
		    _PATH_BTMP);
		जाओ out;
	}

	/* Construct a logininfo and turn it into a utmp */
	स_रखो(&li, 0, माप(li));
	li.type = LTYPE_FAILED;
	li.pid = getpid();
	strlcpy(li.पंक्ति, "ssh:notty", माप(li.पंक्ति));
	strlcpy(li.username, username, माप(li.username));
	strlcpy(li.hostname, hostname, माप(li.hostname));
	समय(&t);
	li.tv_sec = t > 0 ? (अचिन्हित दीर्घ)t : 0;
	अगर (ssh_packet_connection_is_on_socket(ssh)) {
		(व्योम)getpeername(ssh_packet_get_connection_in(ssh),
		    &li.hostaddr.sa, &fromlen);
	}
	construct_utmp(&li, &ut);

	अगर (atomicio(vwrite, fd, &ut, माप(ut)) != माप(ut)) {
		error("Failed to write to %s: %s", _PATH_BTMP,
		    म_त्रुटि(त्रुटि_सं));
	}
out:
	बंद(fd);
}
#पूर्ण_अगर	/* USE_BTMP */
