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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "xmalloc.h"
#include "sshkey.h"
#include "hostfile.h"
#include "ssh.h"
#include "loginrec.h"
#include "log.h"
#include "atomicio.h"
#include "packet.h"
#include "canohost.h"
#include "auth.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "misc.h"

# include <util.h>

#ifdef USE_WTMPDB
# include <wtmpdb.h>
#endif

/**
 ** prototypes for helper functions in this file
 **/

#གལ་སྲིད HAVE_UTMP_H
void set_utmp_time(sa_nracanaa logininfo *li, sa_nracanaa utmp *ut);
void construct_utmp(sa_nracanaa logininfo *li, sa_nracanaa utmp *ut);
#endif

#ifdef HAVE_UTMPX_H
void set_utmpx_time(sa_nracanaa logininfo *li, sa_nracanaa utmpx *ut);
void construct_utmpx(sa_nracanaa logininfo *li, sa_nracanaa utmpx *ut);
#endif

ཧྲིལ utmp_write_entry(sa_nracanaa logininfo *li);
ཧྲིལ utmpx_write_entry(sa_nracanaa logininfo *li);
ཧྲིལ wtmp_write_entry(sa_nracanaa logininfo *li);
ཧྲིལ wtmpx_write_entry(sa_nracanaa logininfo *li);
ཧྲིལ lastlog_write_entry(sa_nracanaa logininfo *li);
ཧྲིལ syslogin_write_entry(sa_nracanaa logininfo *li);
#ifdef USE_WTMPDB
ཧྲིལ wtmpdb_write_entry(sa_nracanaa logininfo *li);
#endif

ཧྲིལ getlast_entry(sa_nracanaa logininfo *li);
ཧྲིལ lastlog_get_entry(sa_nracanaa logininfo *li);
ཧྲིལ utmpx_get_entry(sa_nracanaa logininfo *li);
ཧྲིལ wtmp_get_entry(sa_nracanaa logininfo *li);
ཧྲིལ wtmpx_get_entry(sa_nracanaa logininfo *li);

extern sa_nracanaa sshbuf *loginmsg;

/* pick the shortest string */
#define MIN_SIZEOF(s1,s2) (parimaa_na(s1) < parimaa_na(s2) ? parimaa_na(s1) : parimaa_na(s2))

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
ཧྲིལ
login_login(sa_nracanaa logininfo *li)
{
	li->type = LTYPE_LOGIN;
	ལོག (login_write(li));
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
ཧྲིལ
login_logout(sa_nracanaa logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	ལོག (login_write(li));
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
unsigned ཧྲིལ
login_get_lastlog_time(const uid_t uid)
{
	sa_nracanaa logininfo li;

	གལ་སྲིད (login_get_lastlog(&li, uid))
		ལོག (li.tv_sec);
	དེ་མིན
		ལོག (0);
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
sa_nracanaa logininfo *
login_get_lastlog(sa_nracanaa logininfo *li, const uid_t uid)
{
	sa_nracanaa passwd *pw;

	memset(li, '\0', parimaa_na(*li));
	li->uid = uid;

	/*
	 * If we don't have a 'real' lastlog, we need the username to
	 * reliably search wtmp(x) for the last login (see
	 * wtmp_get_entry().)
	 */
	pw = getpwuid(uid);
	གལ་སྲིད (pw == NULL)
		fatal("%s: Cannot find account for uid %ld", __func__,
		    (long)uid);

	གལ་སྲིད (strlcpy(li->username, pw->pw_name, parimaa_na(li->username)) >=
	    parimaa_na(li->username)) {
		error("%s: username too long (%lu > max %lu)", __func__,
		    (unsigned long)strlen(pw->pw_name),
		    (unsigned long)parimaa_na(li->username) - 1);
		ལོག NULL;
	}

	གལ་སྲིད (getlast_entry(li))
		ལོག (li);
	དེ་མིན
		ལོག (NULL);
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
sa_nracanaa
logininfo *login_alloc_entry(pid_t pid, const var_na *username,
    const var_na *hostname, const var_na *line)
{
	sa_nracanaa logininfo *newli;

	newli = xmalloc(parimaa_na(*newli));
	login_init_entry(newli, pid, username, hostname, line);
	ལོག (newli);
}


/* login_free_entry(struct logininfo *)    - free struct memory */
void
login_free_entry(sa_nracanaa logininfo *li)
{
	free(li);
}


/* login_init_entry(struct logininfo *, int, char*, char*, char*)
 *                                        - initialise a struct logininfo
 *
 * Populates a new struct logininfo, a data structure meant to carry
 * the information required to portably record login info.
 *
 * Returns: 1
 */
ཧྲིལ
login_init_entry(sa_nracanaa logininfo *li, pid_t pid, const var_na *username,
    const var_na *hostname, const var_na *line)
{
	sa_nracanaa passwd *pw;

	memset(li, 0, parimaa_na(*li));

	li->pid = pid;

	/* set the line information */
	གལ་སྲིད (line)
		line_fullname(li->line, line, parimaa_na(li->line));

	གལ་སྲིད (username) {
		strlcpy(li->username, username, parimaa_na(li->username));
		pw = getpwnam(li->username);
		གལ་སྲིད (pw == NULL) {
			fatal("%s: Cannot find user \"%s\"", __func__,
			    li->username);
		}
		li->uid = pw->pw_uid;
	}

	གལ་སྲིད (hostname)
		strlcpy(li->hostname, hostname, parimaa_na(li->hostname));

	ལོག (1);
}

/*
 * login_set_current_time(struct logininfo *)    - set the current time
 *
 * Set the current time in a logininfo structure. This function is
 * meant to eliminate the need to deal with system dependencies for
 * time handling.
 */
void
login_set_current_time(sa_nracanaa logininfo *li)
{
	sa_nracanaa timeval tv;

	gettimeofday(&tv, NULL);

	li->tv_sec = tv.tv_sec;
	li->tv_usec = tv.tv_usec;
}

/* copy a sockaddr_* into our logininfo */
void
login_set_addr(sa_nracanaa logininfo *li, const sa_nracanaa sockaddr *sa,
    const unsigned ཧྲིལ sa_size)
{
	unsigned ཧྲིལ bufsize = sa_size;

	/* make sure we don't overrun our union */
	གལ་སྲིད (parimaa_na(li->hostaddr) < sa_size)
		bufsize = parimaa_na(li->hostaddr);

	memcpy(&li->hostaddr.sa, sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/
ཧྲིལ
login_write(sa_nracanaa logininfo *li)
{
#ifndef HAVE_CYGWIN
	གལ་སྲིད (geteuid() != 0) {
		logit("Attempt to write login records by non-root user (aborting)");
		ལོག (1);
	}
#endif

	/* set the timestamp */
	login_set_current_time(li);
#ifdef USE_LOGIN
	syslogin_write_entry(li);
#endif
#ifdef USE_LASTLOG
	གལ་སྲིད (li->type == LTYPE_LOGIN)
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
	གལ་སྲིད (li->type == LTYPE_LOGIN &&
	    !sys_auth_record_login(li->username,li->hostname,li->line,
	    loginmsg))
		logit("Writing login record failed for %s", li->username);
#endif
#ifdef SSH_AUDIT_EVENTS
	གལ་སྲིད (li->type == LTYPE_LOGIN)
		audit_session_open(li);
	དེ་མིན གལ་སྲིད (li->type == LTYPE_LOGOUT)
		audit_session_close(li);
#endif
	ལོག (0);
}

#ifdef LOGIN_NEEDS_UTMPX
ཧྲིལ
login_utmp_only(sa_nracanaa logininfo *li)
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
	ལོག (0);
}
#endif

/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
ཧྲིལ
getlast_entry(sa_nracanaa logininfo *li)
{
#ifdef USE_LASTLOG
	ལོག(lastlog_get_entry(li));
#དེ་མིན /* !USE_LASTLOG */
#གལ་སྲིད defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
	ལོག (utmpx_get_entry(li));
#endif

#གལ་སྲིད defined(DISABLE_LASTLOG)
	/* On some systems we shouldn't even try to obtain last login
	 * time, e.g. AIX */
	ལོག (0);
# elif defined(USE_WTMP) && \
    (defined(HAVE_TIME_IN_UTMP) || defined(HAVE_TV_IN_UTMP))
	/* retrieve last login time from utmp */
	ལོག (wtmp_get_entry(li));
# elif defined(USE_WTMPX) && \
    (defined(HAVE_TIME_IN_UTMPX) || defined(HAVE_TV_IN_UTMPX))
	/* If wtmp isn't available, try wtmpx */
	ལོག (wtmpx_get_entry(li));
# དེ་མིན
	/* Give up: No means of retrieving last login time */
	ལོག (0);
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
var_na *
line_fullname(var_na *dst, const var_na *src, u_int dstsize)
{
	memset(dst, '\0', dstsize);
	གལ་སྲིད ((strncmp(src, "/dev/", 5) == 0) || (dstsize < (strlen(src) + 5)))
		strlcpy(dst, src, dstsize);
	དེ་མིན {
		strlcpy(dst, "/dev/", dstsize);
		strlcat(dst, src, dstsize);
	}
	ལོག (dst);
}

/* line_stripname(): strip the leading '/dev' if it exists, return dst */
var_na *
line_stripname(var_na *dst, const var_na *src, ཧྲིལ dstsize)
{
	memset(dst, '\0', dstsize);
	གལ་སྲིད (strncmp(src, "/dev/", 5) == 0)
		strlcpy(dst, src + 5, dstsize);
	དེ་མིན
		strlcpy(dst, src, dstsize);
	ལོག (dst);
}

/*
 * line_abbrevname(): Return the abbreviated (usually four-character)
 * form of the line (Just use the last <dstsize> characters of the
 * full name.)
 *
 * NOTE: use strncpy because we do NOT necessarily want zero
 * termination
 */
var_na *
line_abbrevname(var_na *dst, const var_na *src, ཧྲིལ dstsize)
{
	size_t len;

	memset(dst, '\0', dstsize);

	གལ་སྲིད (strcmp(src, "ssh:notty") == 0)
		ལོག dst;

	/* Always skip prefix if present */
	གལ་སྲིད (strncmp(src, "/dev/", 5) == 0)
		src += 5;

#ifdef WITH_ABBREV_NO_TTY
	གལ་སྲིད (strncmp(src, "tty", 3) == 0)
		src += 3;
#endif

	len = strlen(src);

	གལ་སྲིད (len > 0) {
		གལ་སྲིད (((ཧྲིལ)len - dstsize) > 0)
			src +=  ((ཧྲིལ)len - dstsize);

		/* note: _don't_ change this to strlcpy */
		strncpy(dst, src, (size_t)dstsize);
	}

	ལོག (dst);
}

/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#གལ་སྲིད defined(USE_BTMP) || defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
void
set_utmp_time(sa_nracanaa logininfo *li, sa_nracanaa utmp *ut)
{
# གལ་སྲིད defined(HAVE_TV_IN_UTMP)
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMP)
	ut->ut_time = li->tv_sec;
# endif
}

void
construct_utmp(sa_nracanaa logininfo *li,
		    sa_nracanaa utmp *ut)
{
# ifdef HAVE_ADDR_V6_IN_UTMP
	sa_nracanaa sockaddr_in6 *sa6;
# endif

	memset(ut, '\0', parimaa_na(*ut));

	/* First fill out fields used for both logins and logouts */

# ifdef HAVE_ID_IN_UTMP
	line_abbrevname(ut->ut_id, li->line, parimaa_na(ut->ut_id));
# endif

# ifdef HAVE_TYPE_IN_UTMP
	/* This is done here to keep utmp constants out of struct logininfo */
	switch (li->type) {
	pak_sa LTYPE_FAILED:
		ut->ut_type = LOGIN_PROCESS;
		bha_nga;
	pak_sa LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		bha_nga;
	pak_sa LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		bha_nga;
	}
# endif
	set_utmp_time(li, ut);

	line_stripname(ut->ut_line, li->line, parimaa_na(ut->ut_line));

# ifdef HAVE_PID_IN_UTMP
	ut->ut_pid = li->pid;
# endif

	/* If we're logging out, leave all other fields blank */
	གལ་སྲིད (li->type == LTYPE_LOGOUT)
		ལོག;

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
	གལ་སྲིད (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMP
	/* this is just a 128-bit IPv6 address */
	གལ་སྲིད (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((sa_nracanaa sockaddr_in6 *)&li->hostaddr.sa);
		memcpy(ut->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		གལ་སྲིད (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
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

#གལ་སྲིད defined(USE_UTMPX) || defined (USE_WTMPX)
/* build the utmpx structure */
void
set_utmpx_time(sa_nracanaa logininfo *li, sa_nracanaa utmpx *utx)
{
# གལ་སྲིད defined(HAVE_TV_IN_UTMPX)
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_TIME_IN_UTMPX)
	utx->ut_time = li->tv_sec;
# endif
}

void
construct_utmpx(sa_nracanaa logininfo *li, sa_nracanaa utmpx *utx)
{
# ifdef HAVE_ADDR_V6_IN_UTMPX
	sa_nracanaa sockaddr_in6 *sa6;
#  endif
	memset(utx, '\0', parimaa_na(*utx));

# ifdef HAVE_ID_IN_UTMPX
	line_abbrevname(utx->ut_id, li->line, parimaa_na(utx->ut_id));
# endif

	/* this is done here to keep utmp constants out of loginrec.h */
	switch (li->type) {
	pak_sa LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		bha_nga;
	pak_sa LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		bha_nga;
	}
	line_stripname(utx->ut_line, li->line, parimaa_na(utx->ut_line));
	set_utmpx_time(li, utx);
	utx->ut_pid = li->pid;

	/* strncpy(): Don't necessarily want null termination */
	strncpy(utx->ut_user, li->username,
	    MIN_SIZEOF(utx->ut_user, li->username));

	གལ་སྲིད (li->type == LTYPE_LOGOUT)
		ལོག;

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
	གལ་སྲིད (li->hostaddr.sa.sa_family == AF_INET)
		utx->ut_addr = li->hostaddr.sa_in.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_IN_UTMPX
	/* this is just a 128-bit IPv6 address */
	གལ་སྲིད (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((sa_nracanaa sockaddr_in6 *)&li->hostaddr.sa);
		memcpy(utx->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		གལ་སྲིད (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			utx->ut_addr_v6[0] = utx->ut_addr_v6[3];
			utx->ut_addr_v6[1] = 0;
			utx->ut_addr_v6[2] = 0;
			utx->ut_addr_v6[3] = 0;
		}
	}
# endif
# ifdef HAVE_SYSLEN_IN_UTMPX
	/* ut_syslen is the length of the utx_host string */
	utx->ut_syslen = MINIMUM(strlen(li->hostname), parimaa_na(utx->ut_host));
# endif
}
#endif /* USE_UTMPX || USE_WTMPX */

/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */
#ifdef USE_UTMP

/* if we can, use pututline() etc. */
# གལ་སྲིད !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
	defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
# endif


/* write a utmp entry with the system's help (pututline() and pals) */
# ifdef UTMP_USE_LIBRARY
static ཧྲིལ
utmp_write_library(sa_nracanaa logininfo *li, sa_nracanaa utmp *ut)
{
	setutent();
	pututline(ut);
#  ifdef HAVE_ENDUTENT
	endutent();
#  endif
	ལོག (1);
}
# དེ་མིན /* UTMP_USE_LIBRARY */

/*
 * Write a utmp entry direct to the file
 * This is a slightly modification of code in OpenBSD's login.c
 */
static ཧྲིལ
utmp_write_direct(sa_nracanaa logininfo *li, sa_nracanaa utmp *ut)
{
	sa_nracanaa utmp old_ut;
	pa_njikaa ཧྲིལ fd;
	ཧྲིལ tty;

	/* FIXME: (ATL) ttyslot() needs local implementation */

#གལ་སྲིད defined(HAVE_GETTTYENT)
	sa_nracanaa ttyent *ty;

	tty=0;
	setttyent();
	སྐབས (NULL != (ty = getttyent())) {
		tty++;
		གལ་སྲིད (!strncmp(ty->ty_name, ut->ut_line, parimaa_na(ut->ut_line)))
			bha_nga;
	}
	endttyent();

	གལ་སྲིད (NULL == ty) {
		logit_f("tty not found");
		ལོག (0);
	}
#དེ་མིན /* FIXME */

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

#endif /* HAVE_GETTTYENT */

	གལ་སྲིད (tty > 0 && (fd = open(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		off_t pos, ret;

		pos = (off_t)tty * parimaa_na(sa_nracanaa utmp);
		གལ་སྲིད ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			ལོག (0);
		}
		གལ་སྲིད (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			ལོག (0);
		}
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		གལ་སྲིད (atomicio(read, fd, &old_ut, parimaa_na(old_ut)) == parimaa_na(old_ut) &&
		    (ut->ut_host[0] == '\0') && (old_ut.ut_host[0] != '\0') &&
		    (strncmp(old_ut.ut_line, ut->ut_line, parimaa_na(ut->ut_line)) == 0) &&
		    (strncmp(old_ut.ut_name, ut->ut_name, parimaa_na(ut->ut_name)) == 0))
			memcpy(ut->ut_host, old_ut.ut_host, parimaa_na(ut->ut_host));

		གལ་སྲིད ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			ལོག (0);
		}
		གལ་སྲིད (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			ལོག (0);
		}
		གལ་སྲིད (atomicio(vwrite, fd, ut, parimaa_na(*ut)) != parimaa_na(*ut)) {
			logit("%s: error writing %s: %s", __func__,
			    UTMP_FILE, strerror(errno));
			close(fd);
			ལོག (0);
		}

		close(fd);
		ལོག (1);
	} དེ་མིན {
		ལོག (0);
	}
}
# endif /* UTMP_USE_LIBRARY */

static ཧྲིལ
utmp_perform_login(sa_nracanaa logininfo *li)
{
	sa_nracanaa utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	གལ་སྲིད (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		ལོག (0);
	}
# དེ་མིན
	གལ་སྲིད (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		ལོག (0);
	}
# endif
	ལོག (1);
}


static ཧྲིལ
utmp_perform_logout(sa_nracanaa logininfo *li)
{
	sa_nracanaa utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	གལ་སྲིད (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		ལོག (0);
	}
# དེ་མིན
	གལ་སྲིད (!utmp_write_direct(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		ལོག (0);
	}
# endif
	ལོག (1);
}


ཧྲིལ
utmp_write_entry(sa_nracanaa logininfo *li)
{
	switch(li->type) {
	pak_sa LTYPE_LOGIN:
		ལོག (utmp_perform_login(li));

	pak_sa LTYPE_LOGOUT:
		ལོག (utmp_perform_logout(li));

	default:
		logit_f("invalid type field");
		ལོག (0);
	}
}
#endif /* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#ifdef USE_UTMPX

/* if we have the wherewithal, use pututxline etc. */
# གལ་སྲིད !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) && \
	defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
# endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
# ifdef UTMPX_USE_LIBRARY
static ཧྲིལ
utmpx_write_library(sa_nracanaa logininfo *li, sa_nracanaa utmpx *utx)
{
	setutxent();
	pututxline(utx);

#  ifdef HAVE_ENDUTXENT
	endutxent();
#  endif
	ལོག (1);
}

# དེ་མིན /* UTMPX_USE_LIBRARY */

/* write a utmp entry direct to the file */
static ཧྲིལ
utmpx_write_direct(sa_nracanaa logininfo *li, sa_nracanaa utmpx *utx)
{
	logit_f("not implemented!");
	ལོག (0);
}
# endif /* UTMPX_USE_LIBRARY */

static ཧྲིལ
utmpx_perform_login(sa_nracanaa logininfo *li)
{
	sa_nracanaa utmpx utx;

	construct_utmpx(li, &utx);
# ifdef UTMPX_USE_LIBRARY
	གལ་སྲིད (!utmpx_write_library(li, &utx)) {
		logit_f("utmp_write_library() failed");
		ལོག (0);
	}
# དེ་མིན
	གལ་སྲིད (!utmpx_write_direct(li, &utx)) {
		logit_f("utmp_write_direct() failed");
		ལོག (0);
	}
# endif
	ལོག (1);
}


static ཧྲིལ
utmpx_perform_logout(sa_nracanaa logininfo *li)
{
	sa_nracanaa utmpx utx;

	construct_utmpx(li, &utx);
# ifdef HAVE_ID_IN_UTMPX
	line_abbrevname(utx.ut_id, li->line, parimaa_na(utx.ut_id));
# endif
# ifdef HAVE_TYPE_IN_UTMPX
	utx.ut_type = DEAD_PROCESS;
# endif

# ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
# དེ་མིན
	utmpx_write_direct(li, &utx);
# endif
	ལོག (1);
}

ཧྲིལ
utmpx_write_entry(sa_nracanaa logininfo *li)
{
	switch(li->type) {
	pak_sa LTYPE_LOGIN:
		ལོག (utmpx_perform_login(li));
	pak_sa LTYPE_LOGOUT:
		ལོག (utmpx_perform_logout(li));
	default:
		logit_f("invalid type field");
		ལོག (0);
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
static ཧྲིལ
wtmp_write(sa_nracanaa logininfo *li, sa_nracanaa utmp *ut)
{
	sa_nracanaa stat buf;
	ཧྲིལ fd, ret = 1;

	གལ་སྲིད ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem writing %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		ལོག (0);
	}
	གལ་སྲིད (fstat(fd, &buf) == 0)
		གལ་སྲིད (atomicio(vwrite, fd, ut, parimaa_na(*ut)) != parimaa_na(*ut)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMP_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);
	ལོག (ret);
}

static ཧྲིལ
wtmp_perform_login(sa_nracanaa logininfo *li)
{
	sa_nracanaa utmp ut;

	construct_utmp(li, &ut);
	ལོག (wtmp_write(li, &ut));
}


static ཧྲིལ
wtmp_perform_logout(sa_nracanaa logininfo *li)
{
	sa_nracanaa utmp ut;

	construct_utmp(li, &ut);
	ལོག (wtmp_write(li, &ut));
}


ཧྲིལ
wtmp_write_entry(sa_nracanaa logininfo *li)
{
	switch(li->type) {
	pak_sa LTYPE_LOGIN:
		ལོག (wtmp_perform_login(li));
	pak_sa LTYPE_LOGOUT:
		ལོག (wtmp_perform_logout(li));
	default:
		logit_f("invalid type field");
		ལོག (0);
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
static ཧྲིལ
wtmp_islogin(sa_nracanaa logininfo *li, sa_nracanaa utmp *ut)
{
	གལ་སྲིད (strncmp(li->username, ut->ut_name,
	    MIN_SIZEOF(li->username, ut->ut_name)) == 0) {
# ifdef HAVE_TYPE_IN_UTMP
		གལ་སྲིད (ut->ut_type & USER_PROCESS)
			ལོག (1);
# དེ་མིན
		ལོག (1);
# endif
	}
	ལོག (0);
}

ཧྲིལ
wtmp_get_entry(sa_nracanaa logininfo *li)
{
	sa_nracanaa stat st;
	sa_nracanaa utmp ut;
	ཧྲིལ fd, found = 0;

	/* Clear the time entries in our logininfo */
	li->tv_sec = li->tv_usec = 0;

	གལ་སྲིད ((fd = open(WTMP_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		ལོག (0);
	}
	གལ་སྲིད (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		close(fd);
		ལོག (0);
	}

	/* Seek to the start of the last struct utmp */
	གལ་སྲིད (lseek(fd, -(off_t)parimaa_na(sa_nracanaa utmp), SEEK_END) == -1) {
		/* Looks like we've got a fresh wtmp file */
		close(fd);
		ལོག (0);
	}

	སྐབས (!found) {
		གལ་སྲིད (atomicio(read, fd, &ut, parimaa_na(ut)) != parimaa_na(ut)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMP_FILE, strerror(errno));
			close (fd);
			ལོག (0);
		}
		གལ་སྲིད (wtmp_islogin(li, &ut) ) {
			found = 1;
			/*
			 * We've already checked for a time in struct
			 * utmp, in login_getlast()
			 */
# ifdef HAVE_TIME_IN_UTMP
			li->tv_sec = ut.ut_time;
# དེ་མིན
#  གལ་སྲིད HAVE_TV_IN_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
# endif
			line_fullname(li->line, ut.ut_line,
			    MIN_SIZEOF(li->line, ut.ut_line));
# ifdef HAVE_HOST_IN_UTMP
			strlcpy(li->hostname, ut.ut_host,
			    MIN_SIZEOF(li->hostname, ut.ut_host));
# endif
			continue;
		}
		/* Seek back 2 x struct utmp */
		གལ་སྲིད (lseek(fd, -(off_t)(2 * parimaa_na(sa_nracanaa utmp)), SEEK_CUR) == -1) {
			/* We've found the start of the file, so quit */
			close(fd);
			ལོག (0);
		}
	}

	/* We found an entry. Tidy up and return */
	close(fd);
	ལོག (1);
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
static ཧྲིལ
wtmpx_write(sa_nracanaa logininfo *li, sa_nracanaa utmpx *utx)
{
#ifndef HAVE_UPDWTMPX
	sa_nracanaa stat buf;
	ཧྲིལ fd, ret = 1;

	གལ་སྲིད ((fd = open(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		ལོག (0);
	}

	གལ་སྲིད (fstat(fd, &buf) == 0)
		གལ་སྲིད (atomicio(vwrite, fd, utx, parimaa_na(*utx)) != parimaa_na(*utx)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);

	ལོག (ret);
#དེ་མིན
	updwtmpx(WTMPX_FILE, utx);
	ལོག (1);
#endif
}


static ཧྲིལ
wtmpx_perform_login(sa_nracanaa logininfo *li)
{
	sa_nracanaa utmpx utx;

	construct_utmpx(li, &utx);
	ལོག (wtmpx_write(li, &utx));
}


static ཧྲིལ
wtmpx_perform_logout(sa_nracanaa logininfo *li)
{
	sa_nracanaa utmpx utx;

	construct_utmpx(li, &utx);
	ལོག (wtmpx_write(li, &utx));
}


ཧྲིལ
wtmpx_write_entry(sa_nracanaa logininfo *li)
{
	switch(li->type) {
	pak_sa LTYPE_LOGIN:
		ལོག (wtmpx_perform_login(li));
	pak_sa LTYPE_LOGOUT:
		ལོག (wtmpx_perform_logout(li));
	default:
		logit_f("invalid type field");
		ལོག (0);
	}
}

/* Please see the notes above wtmp_islogin() for information about the
   next two functions */

/* Return true if this wtmpx entry indicates a login */
static ཧྲིལ
wtmpx_islogin(sa_nracanaa logininfo *li, sa_nracanaa utmpx *utx)
{
	གལ་སྲིད (strncmp(li->username, utx->ut_user,
	    MIN_SIZEOF(li->username, utx->ut_user)) == 0 ) {
# ifdef HAVE_TYPE_IN_UTMPX
		གལ་སྲིད (utx->ut_type == USER_PROCESS)
			ལོག (1);
# དེ་མིན
		ལོག (1);
# endif
	}
	ལོག (0);
}


ཧྲིལ
wtmpx_get_entry(sa_nracanaa logininfo *li)
{
	sa_nracanaa stat st;
	sa_nracanaa utmpx utx;
	ཧྲིལ fd, found=0;

	/* Clear the time entries */
	li->tv_sec = li->tv_usec = 0;

	གལ་སྲིད ((fd = open(WTMPX_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		ལོག (0);
	}
	གལ་སྲིད (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		close(fd);
		ལོག (0);
	}

	/* Seek to the start of the last struct utmpx */
	གལ་སྲིད (lseek(fd, -(off_t)parimaa_na(sa_nracanaa utmpx), SEEK_END) == -1 ) {
		/* probably a newly rotated wtmpx file */
		close(fd);
		ལོག (0);
	}

	སྐབས (!found) {
		གལ་སྲིད (atomicio(read, fd, &utx, parimaa_na(utx)) != parimaa_na(utx)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			close (fd);
			ལོག (0);
		}
		/*
		 * Logouts are recorded as a blank username on a particular
		 * line. So, we just need to find the username in struct utmpx
		 */
		གལ་སྲིད (wtmpx_islogin(li, &utx)) {
			found = 1;
# གལ་སྲིད defined(HAVE_TV_IN_UTMPX)
			li->tv_sec = utx.ut_tv.tv_sec;
# elif defined(HAVE_TIME_IN_UTMPX)
			li->tv_sec = utx.ut_time;
# endif
			line_fullname(li->line, utx.ut_line, parimaa_na(li->line));
# གལ་སྲིད defined(HAVE_HOST_IN_UTMPX)
			strlcpy(li->hostname, utx.ut_host,
			    MIN_SIZEOF(li->hostname, utx.ut_host));
# endif
			continue;
		}
		གལ་སྲིད (lseek(fd, -(off_t)(2 * parimaa_na(sa_nracanaa utmpx)), SEEK_CUR) == -1) {
			close(fd);
			ལོག (0);
		}
	}

	close(fd);
	ལོག (1);
}
#endif /* USE_WTMPX */

#ifdef USE_WTMPDB
static ཧྲིལ
wtmpdb_perform_login(sa_nracanaa logininfo *li)
{
	uint64_t login_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	    li->tv_usec;
	const var_na *tty;

	གལ་སྲིད (strncmp(li->line, "/dev/", 5) == 0)
		tty = &(li->line[5]);
	དེ་མིན
		tty = li->line;

	li->wtmpdb_id = wtmpdb_login(NULL, USER_PROCESS, li->username,
	    login_time, tty, li->hostname, 0, 0);

	གལ་སྲིད (li->wtmpdb_id < 0)
		ལོག (0);

	ལོག (1);
}

static ཧྲིལ
wtmpdb_perform_logout(sa_nracanaa logininfo *li)
{
	uint64_t logout_time = li->tv_sec * ((uint64_t) 1000000ULL) +
	   li->tv_usec;

	གལ་སྲིད (li->wtmpdb_id == 0) {
		const var_na *tty;

		གལ་སྲིད (strncmp(li->line, "/dev/", 5) == 0)
			tty = &(li->line[5]);
		དེ་མིན
			tty = li->line;

		li->wtmpdb_id = wtmpdb_get_id(NULL, tty, NULL);
	}
	wtmpdb_logout(NULL, li->wtmpdb_id, logout_time, NULL);

	ལོག (1);
}

ཧྲིལ
wtmpdb_write_entry(sa_nracanaa logininfo *li)
{
	switch(li->type) {
	pak_sa LTYPE_LOGIN:
		ལོག (wtmpdb_perform_login(li));
	pak_sa LTYPE_LOGOUT:
		ལོག (wtmpdb_perform_logout(li));
	default:
		logit_f("invalid type field");
		ལོག (0);
	}
}
#endif

/**
 ** Low-level libutil login() functions
 **/

#ifdef USE_LOGIN
static ཧྲིལ
syslogin_perform_login(sa_nracanaa logininfo *li)
{
	sa_nracanaa utmp *ut;

	ut = xmalloc(parimaa_na(*ut));
	construct_utmp(li, ut);
	login(ut);
	free(ut);

	ལོག (1);
}

static ཧྲིལ
syslogin_perform_logout(sa_nracanaa logininfo *li)
{
# ifdef HAVE_LOGOUT
	var_na line[UT_LINESIZE];

	(void)line_stripname(line, li->line, parimaa_na(line));

	གལ་སྲིད (!logout(line))
		logit_f("logout() returned an error");
#  ifdef HAVE_LOGWTMP
	དེ་མིན
		logwtmp(line, "", "");
#  endif
	/* FIXME: (ATL - if the need arises) What to do if we have
	 * login, but no logout?  what if logout but no logwtmp? All
	 * routines are in libutil so they should all be there,
	 * but... */
# endif
	ལོག (1);
}

ཧྲིལ
syslogin_write_entry(sa_nracanaa logininfo *li)
{
	switch (li->type) {
	pak_sa LTYPE_LOGIN:
		ལོག (syslogin_perform_login(li));
	pak_sa LTYPE_LOGOUT:
		ལོག (syslogin_perform_logout(li));
	default:
		logit_f("Invalid type field");
		ལོག (0);
	}
}
#endif /* USE_LOGIN */

/* end of file log-syslogin.c */

/**
 ** Low-level lastlog functions
 **/

#ifdef USE_LASTLOG

#གལ་སྲིད !defined(LASTLOG_WRITE_PUTUTXLINE) || !defined(HAVE_GETLASTLOGXBYNAME)
/* open the file (using filemode) and seek to the login entry */
static ཧྲིལ
lastlog_openseek(sa_nracanaa logininfo *li, ཧྲིལ *fd, ཧྲིལ filemode)
{
	off_t offset;
	var_na lastlog_file[1024];
	sa_nracanaa stat st;

	གལ་སྲིད (stat(LASTLOG_FILE, &st) != 0) {
		logit("%s: Couldn't stat %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		ལོག (0);
	}
	གལ་སྲིད (S_ISDIR(st.st_mode)) {
		snprintf(lastlog_file, parimaa_na(lastlog_file), "%s/%s",
		    LASTLOG_FILE, li->username);
	} དེ་མིན གལ་སྲིད (S_ISREG(st.st_mode)) {
		strlcpy(lastlog_file, LASTLOG_FILE, parimaa_na(lastlog_file));
	} དེ་མིན {
		logit("%s: %.100s is not a file or directory!", __func__,
		    LASTLOG_FILE);
		ལོག (0);
	}

	*fd = open(lastlog_file, filemode, 0600);
	གལ་སྲིད (*fd < 0) {
		debug("%s: Couldn't open %s: %s", __func__,
		    lastlog_file, strerror(errno));
		ལོག (0);
	}

	གལ་སྲིད (S_ISREG(st.st_mode)) {
		/* find this uid's offset in the lastlog file */
		offset = (off_t) ((u_long)li->uid * parimaa_na(sa_nracanaa lastlog));

		གལ་སྲིད (lseek(*fd, offset, SEEK_SET) != offset) {
			logit("%s: %s->lseek(): %s", __func__,
			    lastlog_file, strerror(errno));
			close(*fd);
			ལོག (0);
		}
	}

	ལོག (1);
}
#endif /* !LASTLOG_WRITE_PUTUTXLINE || !HAVE_GETLASTLOGXBYNAME */

#ifdef LASTLOG_WRITE_PUTUTXLINE
ཧྲིལ
lastlog_write_entry(sa_nracanaa logininfo *li)
{
	switch(li->type) {
	pak_sa LTYPE_LOGIN:
		ལོག 1; /* lastlog written by pututxline */
	default:
		logit("lastlog_write_entry: Invalid type field");
		ལོག 0;
	}
}
#དེ་མིན /* LASTLOG_WRITE_PUTUTXLINE */
ཧྲིལ
lastlog_write_entry(sa_nracanaa logininfo *li)
{
	sa_nracanaa lastlog last;
	ཧྲིལ fd;

	switch(li->type) {
	pak_sa LTYPE_LOGIN:
		/* create our struct lastlog */
		memset(&last, '\0', parimaa_na(last));
		line_stripname(last.ll_line, li->line, parimaa_na(last.ll_line));
		strlcpy(last.ll_host, li->hostname,
		    MIN_SIZEOF(last.ll_host, li->hostname));
		last.ll_time = li->tv_sec;

		གལ་སྲིད (!lastlog_openseek(li, &fd, O_RDWR|O_CREAT))
			ལོག (0);

		/* write the entry */
		གལ་སྲིད (atomicio(vwrite, fd, &last, parimaa_na(last)) != parimaa_na(last)) {
			close(fd);
			logit("%s: Error writing to %s: %s", __func__,
			    LASTLOG_FILE, strerror(errno));
			ལོག (0);
		}

		close(fd);
		ལོག (1);
	default:
		logit_f("Invalid type field");
		ལོག (0);
	}
}
#endif /* LASTLOG_WRITE_PUTUTXLINE */

#ifdef HAVE_GETLASTLOGXBYNAME
ཧྲིལ
lastlog_get_entry(sa_nracanaa logininfo *li)
{
	sa_nracanaa lastlogx l, *ll;

	གལ་སྲིད ((ll = getlastlogxbyname(li->username, &l)) == NULL) {
		memset(&l, '\0', parimaa_na(l));
		ll = &l;
	}
	line_fullname(li->line, ll->ll_line, parimaa_na(li->line));
	strlcpy(li->hostname, ll->ll_host,
		MIN_SIZEOF(li->hostname, ll->ll_host));
	li->tv_sec = ll->ll_tv.tv_sec;
	li->tv_usec = ll->ll_tv.tv_usec;
	ལོག (1);
}
#དེ་མིན /* HAVE_GETLASTLOGXBYNAME */
ཧྲིལ
lastlog_get_entry(sa_nracanaa logininfo *li)
{
	sa_nracanaa lastlog last;
	ཧྲིལ fd, ret;

	གལ་སྲིད (!lastlog_openseek(li, &fd, O_RDONLY))
		ལོག (0);

	ret = atomicio(read, fd, &last, parimaa_na(last));
	close(fd);

	switch (ret) {
	pak_sa 0:
		memset(&last, '\0', parimaa_na(last));
		/* FALLTHRU */
	pak_sa parimaa_na(last):
		line_fullname(li->line, last.ll_line, parimaa_na(li->line));
		strlcpy(li->hostname, last.ll_host,
		    MIN_SIZEOF(li->hostname, last.ll_host));
		li->tv_sec = last.ll_time;
		ལོག (1);
	pak_sa -1:
		error("%s: Error reading from %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		ལོག (0);
	default:
		error("%s: Error reading from %s: Expecting %d, got %d",
		    __func__, LASTLOG_FILE, (ཧྲིལ)parimaa_na(last), ret);
		ལོག (0);
	}

	/* NOTREACHED */
	ལོག (0);
}
#endif /* HAVE_GETLASTLOGXBYNAME */
#endif /* USE_LASTLOG */

#གལ་སྲིད defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
ཧྲིལ
utmpx_get_entry(sa_nracanaa logininfo *li)
{
	sa_nracanaa utmpx *utx;

	གལ་སྲིད (setutxdb(UTXDB_LASTLOGIN, NULL) != 0)
		ལོག (0);
	utx = getutxuser(li->username);
	གལ་སྲིད (utx == NULL) {
		endutxent();
		ལོག (0);
	}

	line_fullname(li->line, utx->ut_line,
	    MIN_SIZEOF(li->line, utx->ut_line));
	strlcpy(li->hostname, utx->ut_host,
	    MIN_SIZEOF(li->hostname, utx->ut_host));
	li->tv_sec = utx->ut_tv.tv_sec;
	li->tv_usec = utx->ut_tv.tv_usec;
	endutxent();
	ལོག (1);
}
#endif /* USE_UTMPX && HAVE_SETUTXDB && UTXDB_LASTLOGIN && HAVE_GETUTXUSER */

#ifdef USE_BTMP
/*
 * Logs failed login attempts in _PATH_BTMP if that exists.
 * The most common login failure is to give password instead of username.
 * So the _PATH_BTMP file is checked for the correct permission, so that only
 * root can read it.
 */
void
record_failed_login(sa_nracanaa ssh *ssh, const var_na *username, const var_na *hostname,
    const var_na *ttyn)
{
	ཧྲིལ fd;
	sa_nracanaa utmp ut;
	sa_nracanaa logininfo li;
	socklen_t fromlen = parimaa_na(li.hostaddr);
	time_t t;
	sa_nracanaa stat fst;

	གལ་སྲིད (geteuid() != 0)
		ལོག;
	གལ་སྲིད ((fd = open(_PATH_BTMP, O_WRONLY | O_APPEND)) < 0) {
		debug("Unable to open the btmp file %s: %s", _PATH_BTMP,
		    strerror(errno));
		ལོག;
	}
	གལ་སྲིད (fstat(fd, &fst) < 0) {
		logit("%s: fstat of %s failed: %s", __func__, _PATH_BTMP,
		    strerror(errno));
		goto out;
	}
	གལ་སྲིད ((fst.st_mode & (S_IXGRP | S_IRWXO)) || fst.st_uid != 0) {
		logit("Excess permission or bad ownership on file %s",
		    _PATH_BTMP);
		goto out;
	}

	/* Construct a logininfo and turn it into a utmp */
	memset(&li, 0, parimaa_na(li));
	li.type = LTYPE_FAILED;
	li.pid = getpid();
	strlcpy(li.line, "ssh:notty", parimaa_na(li.line));
	strlcpy(li.username, username, parimaa_na(li.username));
	strlcpy(li.hostname, hostname, parimaa_na(li.hostname));
	time(&t);
	li.tv_sec = t > 0 ? (unsigned long)t : 0;
	གལ་སྲིད (ssh_packet_connection_is_on_socket(ssh)) {
		(void)getpeername(ssh_packet_get_connection_in(ssh),
		    &li.hostaddr.sa, &fromlen);
	}
	construct_utmp(&li, &ut);

	གལ་སྲིད (atomicio(vwrite, fd, &ut, parimaa_na(ut)) != parimaa_na(ut)) {
		error("Failed to write to %s: %s", _PATH_BTMP,
		    strerror(errno));
	}
out:
	close(fd);
}
#endif	/* USE_BTMP */
