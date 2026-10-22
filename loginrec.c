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

#اگر_تعریف_شدہ USE_WTMPDB
# include <wtmpdb.h>
#اگر_ختم

/**
 ** prototypes for helper functions in this file
 **/

#اگر HAVE_UTMP_H
خالی سیٹ_utmp_وقت(ساخت logininfo *li, ساخت utmp *ut);
خالی construct_utmp(ساخت logininfo *li, ساخت utmp *ut);
#اگر_ختم

#اگر_تعریف_شدہ HAVE_UTMPX_H
خالی سیٹ_utmpx_وقت(ساخت logininfo *li, ساخت utmpx *ut);
خالی construct_utmpx(ساخت logininfo *li, ساخت utmpx *ut);
#اگر_ختم

صحیح utmp_write_اندراج(ساخت logininfo *li);
صحیح utmpx_write_اندراج(ساخت logininfo *li);
صحیح wtmp_write_اندراج(ساخت logininfo *li);
صحیح wtmpx_write_اندراج(ساخت logininfo *li);
صحیح lastlog_write_اندراج(ساخت logininfo *li);
صحیح syslogin_write_اندراج(ساخت logininfo *li);
#اگر_تعریف_شدہ USE_WTMPDB
صحیح wtmpdb_write_اندراج(ساخت logininfo *li);
#اگر_ختم

صحیح getlast_اندراج(ساخت logininfo *li);
صحیح lastlog_get_اندراج(ساخت logininfo *li);
صحیح utmpx_get_اندراج(ساخت logininfo *li);
صحیح wtmp_get_اندراج(ساخت logininfo *li);
صحیح wtmpx_get_اندراج(ساخت logininfo *li);

خارجی ساخت sshbuf *loginmsg;

/* pick the shortest string */
#تعریف_کرو MIN_SIZEOF(s1,s2) (حجم(s1) < حجم(s2) ? حجم(s1) : حجم(s2))

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
login_login(ساخت logininfo *li)
{
	li->type = LTYPE_LOGIN;
	واپس (login_write(li));
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
login_logout(ساخت logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	واپس (login_write(li));
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
غیرعلامتی صحیح
login_get_lastlog_وقت(ثابت uid_t uid)
{
	ساخت logininfo li;

	اگر (login_get_lastlog(&li, uid))
		واپس (li.tv_sec);
	ورنہ
		واپس (0);
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
ساخت logininfo *
login_get_lastlog(ساخت logininfo *li, ثابت uid_t uid)
{
	ساخت passwd *pw;

	memset(li, '\0', حجم(*li));
	li->uid = uid;

	/*
	 * If we don't have a 'real' lastlog, we need the username to
	 * reliably search wtmp(x) for the last login (see
	 * wtmp_get_entry().)
	 */
	pw = getpwuid(uid);
	اگر (pw == تہی)
		fatal("%s: Cannot find account for uid %ld", __func__,
		    (طویل)uid);

	اگر (strlcpy(li->username, pw->pw_name, حجم(li->username)) >=
	    حجم(li->username)) {
		error("%s: username too long (%lu > max %lu)", __func__,
		    (غیرعلامتی طویل)لڑی_لمبائی(pw->pw_name),
		    (غیرعلامتی طویل)حجم(li->username) - 1);
		واپس تہی;
	}

	اگر (getlast_اندراج(li))
		واپس (li);
	ورنہ
		واپس (تہی);
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
ساخت
logininfo *login_alloc_اندراج(pid_t pid, ثابت حرف *username,
    ثابت حرف *hostname, ثابت حرف *سطر)
{
	ساخت logininfo *newli;

	newli = xmalloc(حجم(*newli));
	login_init_اندراج(newli, pid, username, hostname, سطر);
	واپس (newli);
}


/* login_free_entry(struct logininfo *)    - free struct memory */
خالی
login_free_اندراج(ساخت logininfo *li)
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
login_init_اندراج(ساخت logininfo *li, pid_t pid, ثابت حرف *username,
    ثابت حرف *hostname, ثابت حرف *سطر)
{
	ساخت passwd *pw;

	memset(li, 0, حجم(*li));

	li->pid = pid;

	/* set the line information */
	اگر (سطر)
		سطر_fullname(li->سطر, سطر, حجم(li->سطر));

	اگر (username) {
		strlcpy(li->username, username, حجم(li->username));
		pw = getpwnam(li->username);
		اگر (pw == تہی) {
			fatal("%s: Cannot find user \"%s\"", __func__,
			    li->username);
		}
		li->uid = pw->pw_uid;
	}

	اگر (hostname)
		strlcpy(li->hostname, hostname, حجم(li->hostname));

	واپس (1);
}

/*
 * login_set_current_time(struct logininfo *)    - set the current time
 *
 * Set the current time in a logininfo structure. This function is
 * meant to eliminate the need to deal with system dependencies for
 * time handling.
 */
خالی
login_سیٹ_current_وقت(ساخت logininfo *li)
{
	ساخت timeval tv;

	gettimeofday(&tv, تہی);

	li->tv_sec = tv.tv_sec;
	li->tv_usec = tv.tv_usec;
}

/* copy a sockaddr_* into our logininfo */
خالی
login_سیٹ_addr(ساخت logininfo *li, ثابت ساخت sockaddr *sa,
    ثابت غیرعلامتی صحیح sa_سائز)
{
	غیرعلامتی صحیح bufsize = sa_سائز;

	/* make sure we don't overrun our union */
	اگر (حجم(li->hostaddr) < sa_سائز)
		bufsize = حجم(li->hostaddr);

	حافظہ_نقل(&li->hostaddr.sa, sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/
صحیح
login_write(ساخت logininfo *li)
{
#اگر_غیر_تعریف_شدہ HAVE_CYGWIN
	اگر (geteuid() != 0) {
		logit("Attempt to write login records by non-root user (aborting)");
		واپس (1);
	}
#اگر_ختم

	/* set the timestamp */
	login_سیٹ_current_وقت(li);
#اگر_تعریف_شدہ USE_LOGIN
	syslogin_write_اندراج(li);
#اگر_ختم
#اگر_تعریف_شدہ USE_LASTLOG
	اگر (li->type == LTYPE_LOGIN)
		lastlog_write_اندراج(li);
#اگر_ختم
#اگر_تعریف_شدہ USE_UTMP
	utmp_write_اندراج(li);
#اگر_ختم
#اگر_تعریف_شدہ USE_WTMP
	wtmp_write_اندراج(li);
#اگر_ختم
#اگر_تعریف_شدہ USE_UTMPX
	utmpx_write_اندراج(li);
#اگر_ختم
#اگر_تعریف_شدہ USE_WTMPX
	wtmpx_write_اندراج(li);
#اگر_ختم
#اگر_تعریف_شدہ USE_WTMPDB
	wtmpdb_write_اندراج(li);
#اگر_ختم
#اگر_تعریف_شدہ CUSTOM_SYS_AUTH_ریکارڈ_LOGIN
	اگر (li->type == LTYPE_LOGIN &&
	    !sys_auth_ریکارڈ_login(li->username,li->hostname,li->سطر,
	    loginmsg))
		logit("Writing login record failed for %s", li->username);
#اگر_ختم
#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
	اگر (li->type == LTYPE_LOGIN)
		audit_session_open(li);
	ورنہ اگر (li->type == LTYPE_LOGOUT)
		audit_session_close(li);
#اگر_ختم
	واپس (0);
}

#اگر_تعریف_شدہ LOGIN_NEEDS_UTMPX
صحیح
login_utmp_only(ساخت logininfo *li)
{
	li->type = LTYPE_LOGIN;
	login_سیٹ_current_وقت(li);
# ifdef USE_UTMP
	utmp_write_اندراج(li);
# endif
# ifdef USE_WTMP
	wtmp_write_اندراج(li);
# endif
# ifdef USE_UTMPX
	utmpx_write_اندراج(li);
# endif
# ifdef USE_WTMPX
	wtmpx_write_اندراج(li);
# endif
	واپس (0);
}
#اگر_ختم

/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
صحیح
getlast_اندراج(ساخت logininfo *li)
{
#اگر_تعریف_شدہ USE_LASTLOG
	واپس(lastlog_get_اندراج(li));
#ورنہ /* !USE_LASTLOG */
#اگر defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
	واپس (utmpx_get_اندراج(li));
#اگر_ختم

#اگر defined(DISABLE_LASTLOG)
	/* On some systems we shouldn't even try to obtain last login
	 * time, e.g. AIX */
	واپس (0);
# elif defined(USE_WTMP) && \
    (defined(HAVE_وقت_اندر_UTMP) || defined(HAVE_TV_اندر_UTMP))
	/* retrieve last login time from utmp */
	واپس (wtmp_get_اندراج(li));
# elif defined(USE_WTMPX) && \
    (defined(HAVE_وقت_اندر_UTMPX) || defined(HAVE_TV_اندر_UTMPX))
	/* If wtmp isn't available, try wtmpx */
	واپس (wtmpx_get_اندراج(li));
# ورنہ
	/* Give up: No means of retrieving last login time */
	واپس (0);
# endif /* DISABLE_LASTLOG */
#اگر_ختم /* USE_LASTLOG */
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
حرف *
سطر_fullname(حرف *dst, ثابت حرف *src, u_int dstsize)
{
	memset(dst, '\0', dstsize);
	اگر ((لڑی_موازنہ(src, "/dev/", 5) == 0) || (dstsize < (لڑی_لمبائی(src) + 5)))
		strlcpy(dst, src, dstsize);
	ورنہ {
		strlcpy(dst, "/dev/", dstsize);
		strlcat(dst, src, dstsize);
	}
	واپس (dst);
}

/* line_stripname(): strip the leading '/dev' if it exists, return dst */
حرف *
سطر_stripname(حرف *dst, ثابت حرف *src, صحیح dstsize)
{
	memset(dst, '\0', dstsize);
	اگر (لڑی_موازنہ(src, "/dev/", 5) == 0)
		strlcpy(dst, src + 5, dstsize);
	ورنہ
		strlcpy(dst, src, dstsize);
	واپس (dst);
}

/*
 * line_abbrevname(): Return the abbreviated (usually four-character)
 * form of the line (Just use the last <dstsize> characters of the
 * full name.)
 *
 * NOTE: use strncpy because we do NOT necessarily want zero
 * termination
 */
حرف *
سطر_abbrevname(حرف *dst, ثابت حرف *src, صحیح dstsize)
{
	سائز_t len;

	memset(dst, '\0', dstsize);

	اگر (strcmp(src, "ssh:notty") == 0)
		واپس dst;

	/* Always skip prefix if present */
	اگر (لڑی_موازنہ(src, "/dev/", 5) == 0)
		src += 5;

#اگر_تعریف_شدہ WITH_ABBREV_NO_TTY
	اگر (لڑی_موازنہ(src, "tty", 3) == 0)
		src += 3;
#اگر_ختم

	len = لڑی_لمبائی(src);

	اگر (len > 0) {
		اگر (((صحیح)len - dstsize) > 0)
			src +=  ((صحیح)len - dstsize);

		/* note: _don't_ change this to strlcpy */
		strncpy(dst, src, (سائز_t)dstsize);
	}

	واپس (dst);
}

/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#اگر defined(USE_BTMP) || defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
خالی
سیٹ_utmp_وقت(ساخت logininfo *li, ساخت utmp *ut)
{
# اگر defined(HAVE_TV_اندر_UTMP)
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_وقت_اندر_UTMP)
	ut->ut_وقت = li->tv_sec;
# endif
}

خالی
construct_utmp(ساخت logininfo *li,
		    ساخت utmp *ut)
{
# ifdef HAVE_ADDR_V6_اندر_UTMP
	ساخت sockaddr_in6 *sa6;
# endif

	memset(ut, '\0', حجم(*ut));

	/* First fill out fields used for both logins and logouts */

# ifdef HAVE_ID_اندر_UTMP
	سطر_abbrevname(ut->ut_id, li->سطر, حجم(ut->ut_id));
# endif

# ifdef HAVE_TYPE_اندر_UTMP
	/* This is done here to keep utmp constants out of struct logininfo */
	انتخاب (li->type) {
	حالت LTYPE_FAILED:
		ut->ut_type = LOGIN_PROCESS;
		توڑو;
	حالت LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		توڑو;
	حالت LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		توڑو;
	}
# endif
	سیٹ_utmp_وقت(li, ut);

	سطر_stripname(ut->ut_سطر, li->سطر, حجم(ut->ut_سطر));

# ifdef HAVE_PID_اندر_UTMP
	ut->ut_pid = li->pid;
# endif

	/* If we're logging out, leave all other fields blank */
	اگر (li->type == LTYPE_LOGOUT)
		واپس;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

	/* Use strncpy because we don't necessarily want null termination */
	strncpy(ut->ut_name, li->username,
	    MIN_SIZEOF(ut->ut_name, li->username));
# ifdef HAVE_HOST_اندر_UTMP
	strncpy(ut->ut_host, li->hostname,
	    MIN_SIZEOF(ut->ut_host, li->hostname));
# endif
# ifdef HAVE_ADDR_اندر_UTMP
	/* this is just a 32-bit IP address */
	اگر (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_اندر.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_اندر_UTMP
	/* this is just a 128-bit IPv6 address */
	اگر (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((ساخت sockaddr_in6 *)&li->hostaddr.sa);
		حافظہ_نقل(ut->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		اگر (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			ut->ut_addr_v6[0] = ut->ut_addr_v6[3];
			ut->ut_addr_v6[1] = 0;
			ut->ut_addr_v6[2] = 0;
			ut->ut_addr_v6[3] = 0;
		}
	}
# endif
}
#اگر_ختم /* USE_BTMP || USE_UTMP || USE_WTMP || USE_LOGIN */

/**
 ** utmpx utility functions
 **
 ** These functions manipulate struct utmpx, accounting for system
 ** variations.
 **/

#اگر defined(USE_UTMPX) || defined (USE_WTMPX)
/* build the utmpx structure */
خالی
سیٹ_utmpx_وقت(ساخت logininfo *li, ساخت utmpx *utx)
{
# اگر defined(HAVE_TV_اندر_UTMPX)
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_وقت_اندر_UTMPX)
	utx->ut_وقت = li->tv_sec;
# endif
}

خالی
construct_utmpx(ساخت logininfo *li, ساخت utmpx *utx)
{
# ifdef HAVE_ADDR_V6_اندر_UTMPX
	ساخت sockaddr_in6 *sa6;
#  endif
	memset(utx, '\0', حجم(*utx));

# ifdef HAVE_ID_اندر_UTMPX
	سطر_abbrevname(utx->ut_id, li->سطر, حجم(utx->ut_id));
# endif

	/* this is done here to keep utmp constants out of loginrec.h */
	انتخاب (li->type) {
	حالت LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		توڑو;
	حالت LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		توڑو;
	}
	سطر_stripname(utx->ut_سطر, li->سطر, حجم(utx->ut_سطر));
	سیٹ_utmpx_وقت(li, utx);
	utx->ut_pid = li->pid;

	/* strncpy(): Don't necessarily want null termination */
	strncpy(utx->ut_user, li->username,
	    MIN_SIZEOF(utx->ut_user, li->username));

	اگر (li->type == LTYPE_LOGOUT)
		واپس;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

# ifdef HAVE_HOST_اندر_UTMPX
	strncpy(utx->ut_host, li->hostname,
	    MIN_SIZEOF(utx->ut_host, li->hostname));
# endif
# ifdef HAVE_SS_اندر_UTMPX
	utx->ut_ss = li->hostaddr.sa_storage;
# endif
# ifdef HAVE_ADDR_اندر_UTMPX
	/* this is just a 32-bit IP address */
	اگر (li->hostaddr.sa.sa_family == AF_INET)
		utx->ut_addr = li->hostaddr.sa_اندر.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_اندر_UTMPX
	/* this is just a 128-bit IPv6 address */
	اگر (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((ساخت sockaddr_in6 *)&li->hostaddr.sa);
		حافظہ_نقل(utx->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		اگر (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			utx->ut_addr_v6[0] = utx->ut_addr_v6[3];
			utx->ut_addr_v6[1] = 0;
			utx->ut_addr_v6[2] = 0;
			utx->ut_addr_v6[3] = 0;
		}
	}
# endif
# ifdef HAVE_SYSLEN_اندر_UTMPX
	/* ut_syslen is the length of the utx_host string */
	utx->ut_syslen = MINIMUM(لڑی_لمبائی(li->hostname), حجم(utx->ut_host));
# endif
}
#اگر_ختم /* USE_UTMPX || USE_WTMPX */

/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */
#اگر_تعریف_شدہ USE_UTMP

/* if we can, use pututline() etc. */
# اگر !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
	defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
# endif


/* write a utmp entry with the system's help (pututline() and pals) */
# ifdef UTMP_USE_LIBRARY
ساکن صحیح
utmp_write_library(ساخت logininfo *li, ساخت utmp *ut)
{
	setutent();
	pututline(ut);
#  ifdef HAVE_ENDUTENT
	endutent();
#  endif
	واپس (1);
}
# ورنہ /* UTMP_USE_LIBRARY */

/*
 * Write a utmp entry direct to the file
 * This is a slightly modification of code in OpenBSD's login.c
 */
ساکن صحیح
utmp_write_براہ_راست(ساخت logininfo *li, ساخت utmp *ut)
{
	ساخت utmp old_ut;
	اندراج صحیح fd;
	صحیح tty;

	/* FIXME: (ATL) ttyslot() needs local implementation */

#اگر defined(HAVE_GETTTYENT)
	ساخت ttyent *ty;

	tty=0;
	setttyent();
	جب (تہی != (ty = getttyent())) {
		tty++;
		اگر (!لڑی_موازنہ(ty->ty_name, ut->ut_سطر, حجم(ut->ut_سطر)))
			توڑو;
	}
	endttyent();

	اگر (تہی == ty) {
		logit_f("tty not found");
		واپس (0);
	}
#ورنہ /* FIXME */

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

#اگر_ختم /* HAVE_GETTTYENT */

	اگر (tty > 0 && (fd = open(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		off_t pos, ret;

		pos = (off_t)tty * حجم(ساخت utmp);
		اگر ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			واپس (0);
		}
		اگر (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			واپس (0);
		}
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		اگر (atomicio(اقرأ, fd, &old_ut, حجم(old_ut)) == حجم(old_ut) &&
		    (ut->ut_host[0] == '\0') && (old_ut.ut_host[0] != '\0') &&
		    (لڑی_موازنہ(old_ut.ut_سطر, ut->ut_سطر, حجم(ut->ut_سطر)) == 0) &&
		    (لڑی_موازنہ(old_ut.ut_name, ut->ut_name, حجم(ut->ut_name)) == 0))
			حافظہ_نقل(ut->ut_host, old_ut.ut_host, حجم(ut->ut_host));

		اگر ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			واپس (0);
		}
		اگر (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			واپس (0);
		}
		اگر (atomicio(vwrite, fd, ut, حجم(*ut)) != حجم(*ut)) {
			logit("%s: error writing %s: %s", __func__,
			    UTMP_FILE, strerror(errno));
			close(fd);
			واپس (0);
		}

		close(fd);
		واپس (1);
	} ورنہ {
		واپس (0);
	}
}
# endif /* UTMP_USE_LIBRARY */

ساکن صحیح
utmp_perform_login(ساخت logininfo *li)
{
	ساخت utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	اگر (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		واپس (0);
	}
# ورنہ
	اگر (!utmp_write_براہ_راست(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		واپس (0);
	}
# endif
	واپس (1);
}


ساکن صحیح
utmp_perform_logout(ساخت logininfo *li)
{
	ساخت utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	اگر (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		واپس (0);
	}
# ورنہ
	اگر (!utmp_write_براہ_راست(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		واپس (0);
	}
# endif
	واپس (1);
}


صحیح
utmp_write_اندراج(ساخت logininfo *li)
{
	انتخاب(li->type) {
	حالت LTYPE_LOGIN:
		واپس (utmp_perform_login(li));

	حالت LTYPE_LOGOUT:
		واپس (utmp_perform_logout(li));

	طےشدہ:
		logit_f("invalid type field");
		واپس (0);
	}
}
#اگر_ختم /* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#اگر_تعریف_شدہ USE_UTMPX

/* if we have the wherewithal, use pututxline etc. */
# اگر !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) && \
	defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
# endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
# ifdef UTMPX_USE_LIBRARY
ساکن صحیح
utmpx_write_library(ساخت logininfo *li, ساخت utmpx *utx)
{
	setutxent();
	pututxline(utx);

#  ifdef HAVE_ENDUTXENT
	endutxent();
#  endif
	واپس (1);
}

# ورنہ /* UTMPX_USE_LIBRARY */

/* write a utmp entry direct to the file */
ساکن صحیح
utmpx_write_براہ_راست(ساخت logininfo *li, ساخت utmpx *utx)
{
	logit_f("not implemented!");
	واپس (0);
}
# endif /* UTMPX_USE_LIBRARY */

ساکن صحیح
utmpx_perform_login(ساخت logininfo *li)
{
	ساخت utmpx utx;

	construct_utmpx(li, &utx);
# ifdef UTMPX_USE_LIBRARY
	اگر (!utmpx_write_library(li, &utx)) {
		logit_f("utmp_write_library() failed");
		واپس (0);
	}
# ورنہ
	اگر (!utmpx_write_براہ_راست(li, &utx)) {
		logit_f("utmp_write_direct() failed");
		واپس (0);
	}
# endif
	واپس (1);
}


ساکن صحیح
utmpx_perform_logout(ساخت logininfo *li)
{
	ساخت utmpx utx;

	construct_utmpx(li, &utx);
# ifdef HAVE_ID_اندر_UTMPX
	سطر_abbrevname(utx.ut_id, li->سطر, حجم(utx.ut_id));
# endif
# ifdef HAVE_TYPE_اندر_UTMPX
	utx.ut_type = DEAD_PROCESS;
# endif

# ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
# ورنہ
	utmpx_write_براہ_راست(li, &utx);
# endif
	واپس (1);
}

صحیح
utmpx_write_اندراج(ساخت logininfo *li)
{
	انتخاب(li->type) {
	حالت LTYPE_LOGIN:
		واپس (utmpx_perform_login(li));
	حالت LTYPE_LOGOUT:
		واپس (utmpx_perform_logout(li));
	طےشدہ:
		logit_f("invalid type field");
		واپس (0);
	}
}
#اگر_ختم /* USE_UTMPX */


/**
 ** Low-level wtmp functions
 **/

#اگر_تعریف_شدہ USE_WTMP

/*
 * Write a wtmp entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
ساکن صحیح
wtmp_write(ساخت logininfo *li, ساخت utmp *ut)
{
	ساخت stat buf;
	صحیح fd, ret = 1;

	اگر ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem writing %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		واپس (0);
	}
	اگر (fstat(fd, &buf) == 0)
		اگر (atomicio(vwrite, fd, ut, حجم(*ut)) != حجم(*ut)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMP_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);
	واپس (ret);
}

ساکن صحیح
wtmp_perform_login(ساخت logininfo *li)
{
	ساخت utmp ut;

	construct_utmp(li, &ut);
	واپس (wtmp_write(li, &ut));
}


ساکن صحیح
wtmp_perform_logout(ساخت logininfo *li)
{
	ساخت utmp ut;

	construct_utmp(li, &ut);
	واپس (wtmp_write(li, &ut));
}


صحیح
wtmp_write_اندراج(ساخت logininfo *li)
{
	انتخاب(li->type) {
	حالت LTYPE_LOGIN:
		واپس (wtmp_perform_login(li));
	حالت LTYPE_LOGOUT:
		واپس (wtmp_perform_logout(li));
	طےشدہ:
		logit_f("invalid type field");
		واپس (0);
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
ساکن صحیح
wtmp_islogin(ساخت logininfo *li, ساخت utmp *ut)
{
	اگر (لڑی_موازنہ(li->username, ut->ut_name,
	    MIN_SIZEOF(li->username, ut->ut_name)) == 0) {
# ifdef HAVE_TYPE_اندر_UTMP
		اگر (ut->ut_type & USER_PROCESS)
			واپس (1);
# ورنہ
		واپس (1);
# endif
	}
	واپس (0);
}

صحیح
wtmp_get_اندراج(ساخت logininfo *li)
{
	ساخت stat st;
	ساخت utmp ut;
	صحیح fd, ملا = 0;

	/* Clear the time entries in our logininfo */
	li->tv_sec = li->tv_usec = 0;

	اگر ((fd = open(WTMP_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		واپس (0);
	}
	اگر (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		close(fd);
		واپس (0);
	}

	/* Seek to the start of the last struct utmp */
	اگر (lseek(fd, -(off_t)حجم(ساخت utmp), SEEK_END) == -1) {
		/* Looks like we've got a fresh wtmp file */
		close(fd);
		واپس (0);
	}

	جب (!ملا) {
		اگر (atomicio(اقرأ, fd, &ut, حجم(ut)) != حجم(ut)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMP_FILE, strerror(errno));
			close (fd);
			واپس (0);
		}
		اگر (wtmp_islogin(li, &ut) ) {
			ملا = 1;
			/*
			 * We've already checked for a time in struct
			 * utmp, in login_getlast()
			 */
# ifdef HAVE_وقت_اندر_UTMP
			li->tv_sec = ut.ut_وقت;
# ورنہ
#  اگر HAVE_TV_اندر_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
# endif
			سطر_fullname(li->سطر, ut.ut_سطر,
			    MIN_SIZEOF(li->سطر, ut.ut_سطر));
# ifdef HAVE_HOST_اندر_UTMP
			strlcpy(li->hostname, ut.ut_host,
			    MIN_SIZEOF(li->hostname, ut.ut_host));
# endif
			جاری;
		}
		/* Seek back 2 x struct utmp */
		اگر (lseek(fd, -(off_t)(2 * حجم(ساخت utmp)), SEEK_CUR) == -1) {
			/* We've found the start of the file, so quit */
			close(fd);
			واپس (0);
		}
	}

	/* We found an entry. Tidy up and return */
	close(fd);
	واپس (1);
}
# endif /* USE_WTMP */


/**
 ** Low-level wtmpx functions
 **/

#اگر_تعریف_شدہ USE_WTMPX
/*
 * Write a wtmpx entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
ساکن صحیح
wtmpx_write(ساخت logininfo *li, ساخت utmpx *utx)
{
#اگر_غیر_تعریف_شدہ HAVE_UPDWTMPX
	ساخت stat buf;
	صحیح fd, ret = 1;

	اگر ((fd = open(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		واپس (0);
	}

	اگر (fstat(fd, &buf) == 0)
		اگر (atomicio(vwrite, fd, utx, حجم(*utx)) != حجم(*utx)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);

	واپس (ret);
#ورنہ
	updwtmpx(WTMPX_FILE, utx);
	واپس (1);
#اگر_ختم
}


ساکن صحیح
wtmpx_perform_login(ساخت logininfo *li)
{
	ساخت utmpx utx;

	construct_utmpx(li, &utx);
	واپس (wtmpx_write(li, &utx));
}


ساکن صحیح
wtmpx_perform_logout(ساخت logininfo *li)
{
	ساخت utmpx utx;

	construct_utmpx(li, &utx);
	واپس (wtmpx_write(li, &utx));
}


صحیح
wtmpx_write_اندراج(ساخت logininfo *li)
{
	انتخاب(li->type) {
	حالت LTYPE_LOGIN:
		واپس (wtmpx_perform_login(li));
	حالت LTYPE_LOGOUT:
		واپس (wtmpx_perform_logout(li));
	طےشدہ:
		logit_f("invalid type field");
		واپس (0);
	}
}

/* Please see the notes above wtmp_islogin() for information about the
   next two functions */

/* Return true if this wtmpx entry indicates a login */
ساکن صحیح
wtmpx_islogin(ساخت logininfo *li, ساخت utmpx *utx)
{
	اگر (لڑی_موازنہ(li->username, utx->ut_user,
	    MIN_SIZEOF(li->username, utx->ut_user)) == 0 ) {
# ifdef HAVE_TYPE_اندر_UTMPX
		اگر (utx->ut_type == USER_PROCESS)
			واپس (1);
# ورنہ
		واپس (1);
# endif
	}
	واپس (0);
}


صحیح
wtmpx_get_اندراج(ساخت logininfo *li)
{
	ساخت stat st;
	ساخت utmpx utx;
	صحیح fd, ملا=0;

	/* Clear the time entries */
	li->tv_sec = li->tv_usec = 0;

	اگر ((fd = open(WTMPX_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		واپس (0);
	}
	اگر (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		close(fd);
		واپس (0);
	}

	/* Seek to the start of the last struct utmpx */
	اگر (lseek(fd, -(off_t)حجم(ساخت utmpx), SEEK_END) == -1 ) {
		/* probably a newly rotated wtmpx file */
		close(fd);
		واپس (0);
	}

	جب (!ملا) {
		اگر (atomicio(اقرأ, fd, &utx, حجم(utx)) != حجم(utx)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			close (fd);
			واپس (0);
		}
		/*
		 * Logouts are recorded as a blank username on a particular
		 * line. So, we just need to find the username in struct utmpx
		 */
		اگر (wtmpx_islogin(li, &utx)) {
			ملا = 1;
# اگر defined(HAVE_TV_اندر_UTMPX)
			li->tv_sec = utx.ut_tv.tv_sec;
# elif defined(HAVE_وقت_اندر_UTMPX)
			li->tv_sec = utx.ut_وقت;
# endif
			سطر_fullname(li->سطر, utx.ut_سطر, حجم(li->سطر));
# اگر defined(HAVE_HOST_اندر_UTMPX)
			strlcpy(li->hostname, utx.ut_host,
			    MIN_SIZEOF(li->hostname, utx.ut_host));
# endif
			جاری;
		}
		اگر (lseek(fd, -(off_t)(2 * حجم(ساخت utmpx)), SEEK_CUR) == -1) {
			close(fd);
			واپس (0);
		}
	}

	close(fd);
	واپس (1);
}
#اگر_ختم /* USE_WTMPX */

#اگر_تعریف_شدہ USE_WTMPDB
ساکن صحیح
wtmpdb_perform_login(ساخت logininfo *li)
{
	uint64_t login_وقت = li->tv_sec * ((uint64_t) 1000000ULL) +
	    li->tv_usec;
	ثابت حرف *tty;

	اگر (لڑی_موازنہ(li->سطر, "/dev/", 5) == 0)
		tty = &(li->سطر[5]);
	ورنہ
		tty = li->سطر;

	li->wtmpdb_id = wtmpdb_login(تہی, USER_PROCESS, li->username,
	    login_وقت, tty, li->hostname, 0, 0);

	اگر (li->wtmpdb_id < 0)
		واپس (0);

	واپس (1);
}

ساکن صحیح
wtmpdb_perform_logout(ساخت logininfo *li)
{
	uint64_t logout_وقت = li->tv_sec * ((uint64_t) 1000000ULL) +
	   li->tv_usec;

	اگر (li->wtmpdb_id == 0) {
		ثابت حرف *tty;

		اگر (لڑی_موازنہ(li->سطر, "/dev/", 5) == 0)
			tty = &(li->سطر[5]);
		ورنہ
			tty = li->سطر;

		li->wtmpdb_id = wtmpdb_get_id(تہی, tty, تہی);
	}
	wtmpdb_logout(تہی, li->wtmpdb_id, logout_وقت, تہی);

	واپس (1);
}

صحیح
wtmpdb_write_اندراج(ساخت logininfo *li)
{
	انتخاب(li->type) {
	حالت LTYPE_LOGIN:
		واپس (wtmpdb_perform_login(li));
	حالت LTYPE_LOGOUT:
		واپس (wtmpdb_perform_logout(li));
	طےشدہ:
		logit_f("invalid type field");
		واپس (0);
	}
}
#اگر_ختم

/**
 ** Low-level libutil login() functions
 **/

#اگر_تعریف_شدہ USE_LOGIN
ساکن صحیح
syslogin_perform_login(ساخت logininfo *li)
{
	ساخت utmp *ut;

	ut = xmalloc(حجم(*ut));
	construct_utmp(li, ut);
	login(ut);
	آزاد(ut);

	واپس (1);
}

ساکن صحیح
syslogin_perform_logout(ساخت logininfo *li)
{
# ifdef HAVE_LOGOUT
	حرف سطر[UT_LINESIZE];

	(خالی)سطر_stripname(سطر, li->سطر, حجم(سطر));

	اگر (!logout(سطر))
		logit_f("logout() returned an error");
#  ifdef HAVE_LOGWTMP
	ورنہ
		logwtmp(سطر, "", "");
#  endif
	/* FIXME: (ATL - if the need arises) What to do if we have
	 * login, but no logout?  what if logout but no logwtmp? All
	 * routines are in libutil so they should all be there,
	 * but... */
# endif
	واپس (1);
}

صحیح
syslogin_write_اندراج(ساخت logininfo *li)
{
	انتخاب (li->type) {
	حالت LTYPE_LOGIN:
		واپس (syslogin_perform_login(li));
	حالت LTYPE_LOGOUT:
		واپس (syslogin_perform_logout(li));
	طےشدہ:
		logit_f("Invalid type field");
		واپس (0);
	}
}
#اگر_ختم /* USE_LOGIN */

/* end of file log-syslogin.c */

/**
 ** Low-level lastlog functions
 **/

#اگر_تعریف_شدہ USE_LASTLOG

#اگر !defined(LASTLOG_WRITE_PUTUTXLINE) || !defined(HAVE_GETLASTLOGXBYNAME)
/* open the file (using filemode) and seek to the login entry */
ساکن صحیح
lastlog_openseek(ساخت logininfo *li, صحیح *fd, صحیح filemode)
{
	off_t انحراف;
	حرف lastlog_file[1024];
	ساخت stat st;

	اگر (stat(LASTLOG_FILE, &st) != 0) {
		logit("%s: Couldn't stat %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		واپس (0);
	}
	اگر (S_ISDIR(st.st_mode)) {
		snprintf(lastlog_file, حجم(lastlog_file), "%s/%s",
		    LASTLOG_FILE, li->username);
	} ورنہ اگر (S_ISREG(st.st_mode)) {
		strlcpy(lastlog_file, LASTLOG_FILE, حجم(lastlog_file));
	} ورنہ {
		logit("%s: %.100s is not a file or directory!", __func__,
		    LASTLOG_FILE);
		واپس (0);
	}

	*fd = open(lastlog_file, filemode, 0600);
	اگر (*fd < 0) {
		debug("%s: Couldn't open %s: %s", __func__,
		    lastlog_file, strerror(errno));
		واپس (0);
	}

	اگر (S_ISREG(st.st_mode)) {
		/* find this uid's offset in the lastlog file */
		انحراف = (off_t) ((u_long)li->uid * حجم(ساخت lastlog));

		اگر (lseek(*fd, انحراف, SEEK_SET) != انحراف) {
			logit("%s: %s->lseek(): %s", __func__,
			    lastlog_file, strerror(errno));
			close(*fd);
			واپس (0);
		}
	}

	واپس (1);
}
#اگر_ختم /* !LASTLOG_WRITE_PUTUTXLINE || !HAVE_GETLASTLOGXBYNAME */

#اگر_تعریف_شدہ LASTLOG_WRITE_PUTUTXLINE
صحیح
lastlog_write_اندراج(ساخت logininfo *li)
{
	انتخاب(li->type) {
	حالت LTYPE_LOGIN:
		واپس 1; /* lastlog written by pututxline */
	طےشدہ:
		logit("lastlog_write_entry: Invalid type field");
		واپس 0;
	}
}
#ورنہ /* LASTLOG_WRITE_PUTUTXLINE */
صحیح
lastlog_write_اندراج(ساخت logininfo *li)
{
	ساخت lastlog آخری;
	صحیح fd;

	انتخاب(li->type) {
	حالت LTYPE_LOGIN:
		/* create our struct lastlog */
		memset(&آخری, '\0', حجم(آخری));
		سطر_stripname(آخری.ll_سطر, li->سطر, حجم(آخری.ll_سطر));
		strlcpy(آخری.ll_host, li->hostname,
		    MIN_SIZEOF(آخری.ll_host, li->hostname));
		آخری.ll_وقت = li->tv_sec;

		اگر (!lastlog_openseek(li, &fd, O_RDWR|O_CREAT))
			واپس (0);

		/* write the entry */
		اگر (atomicio(vwrite, fd, &آخری, حجم(آخری)) != حجم(آخری)) {
			close(fd);
			logit("%s: Error writing to %s: %s", __func__,
			    LASTLOG_FILE, strerror(errno));
			واپس (0);
		}

		close(fd);
		واپس (1);
	طےشدہ:
		logit_f("Invalid type field");
		واپس (0);
	}
}
#اگر_ختم /* LASTLOG_WRITE_PUTUTXLINE */

#اگر_تعریف_شدہ HAVE_GETLASTLOGXBYNAME
صحیح
lastlog_get_اندراج(ساخت logininfo *li)
{
	ساخت lastlogx l, *ll;

	اگر ((ll = getlastlogxbyname(li->username, &l)) == تہی) {
		memset(&l, '\0', حجم(l));
		ll = &l;
	}
	سطر_fullname(li->سطر, ll->ll_سطر, حجم(li->سطر));
	strlcpy(li->hostname, ll->ll_host,
		MIN_SIZEOF(li->hostname, ll->ll_host));
	li->tv_sec = ll->ll_tv.tv_sec;
	li->tv_usec = ll->ll_tv.tv_usec;
	واپس (1);
}
#ورنہ /* HAVE_GETLASTLOGXBYNAME */
صحیح
lastlog_get_اندراج(ساخت logininfo *li)
{
	ساخت lastlog آخری;
	صحیح fd, ret;

	اگر (!lastlog_openseek(li, &fd, O_RDONLY))
		واپس (0);

	ret = atomicio(اقرأ, fd, &آخری, حجم(آخری));
	close(fd);

	انتخاب (ret) {
	حالت 0:
		memset(&آخری, '\0', حجم(آخری));
		/* FALLTHRU */
	حالت حجم(آخری):
		سطر_fullname(li->سطر, آخری.ll_سطر, حجم(li->سطر));
		strlcpy(li->hostname, آخری.ll_host,
		    MIN_SIZEOF(li->hostname, آخری.ll_host));
		li->tv_sec = آخری.ll_وقت;
		واپس (1);
	حالت -1:
		error("%s: Error reading from %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		واپس (0);
	طےشدہ:
		error("%s: Error reading from %s: Expecting %d, got %d",
		    __func__, LASTLOG_FILE, (صحیح)حجم(آخری), ret);
		واپس (0);
	}

	/* NOTREACHED */
	واپس (0);
}
#اگر_ختم /* HAVE_GETLASTLOGXBYNAME */
#اگر_ختم /* USE_LASTLOG */

#اگر defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
صحیح
utmpx_get_اندراج(ساخت logininfo *li)
{
	ساخت utmpx *utx;

	اگر (setutxdb(UTXDB_LASTLOGIN, تہی) != 0)
		واپس (0);
	utx = getutxuser(li->username);
	اگر (utx == تہی) {
		endutxent();
		واپس (0);
	}

	سطر_fullname(li->سطر, utx->ut_سطر,
	    MIN_SIZEOF(li->سطر, utx->ut_سطر));
	strlcpy(li->hostname, utx->ut_host,
	    MIN_SIZEOF(li->hostname, utx->ut_host));
	li->tv_sec = utx->ut_tv.tv_sec;
	li->tv_usec = utx->ut_tv.tv_usec;
	endutxent();
	واپس (1);
}
#اگر_ختم /* USE_UTMPX && HAVE_SETUTXDB && UTXDB_LASTLOGIN && HAVE_GETUTXUSER */

#اگر_تعریف_شدہ USE_BTMP
/*
 * Logs failed login attempts in _PATH_BTMP if that exists.
 * The most common login failure is to give password instead of username.
 * So the _PATH_BTMP file is checked for the correct permission, so that only
 * root can read it.
 */
خالی
ریکارڈ_failed_login(ساخت ssh *ssh, ثابت حرف *username, ثابت حرف *hostname,
    ثابت حرف *ttyn)
{
	صحیح fd;
	ساخت utmp ut;
	ساخت logininfo li;
	socklen_t fromlen = حجم(li.hostaddr);
	time_t t;
	ساخت stat fst;

	اگر (geteuid() != 0)
		واپس;
	اگر ((fd = open(راستہ_BTMP, O_WRONLY | O_APPEND)) < 0) {
		debug("Unable to open the btmp file %s: %s", راستہ_BTMP,
		    strerror(errno));
		واپس;
	}
	اگر (fstat(fd, &fst) < 0) {
		logit("%s: fstat of %s failed: %s", __func__, راستہ_BTMP,
		    strerror(errno));
		جاؤ برآمد;
	}
	اگر ((fst.st_mode & (S_IXGRP | S_IRWXO)) || fst.st_uid != 0) {
		logit("Excess permission or bad ownership on file %s",
		    راستہ_BTMP);
		جاؤ برآمد;
	}

	/* Construct a logininfo and turn it into a utmp */
	memset(&li, 0, حجم(li));
	li.type = LTYPE_FAILED;
	li.pid = getpid();
	strlcpy(li.سطر, "ssh:notty", حجم(li.سطر));
	strlcpy(li.username, username, حجم(li.username));
	strlcpy(li.hostname, hostname, حجم(li.hostname));
	time(&t);
	li.tv_sec = t > 0 ? (غیرعلامتی طویل)t : 0;
	اگر (ssh_packet_connection_is_on_socket(ssh)) {
		(خالی)getpeername(ssh_packet_get_connection_اندر(ssh),
		    &li.hostaddr.sa, &fromlen);
	}
	construct_utmp(&li, &ut);

	اگر (atomicio(vwrite, fd, &ut, حجم(ut)) != حجم(ut)) {
		error("Failed to write to %s: %s", راستہ_BTMP,
		    strerror(errno));
	}
برآمد:
	close(fd);
}
#اگر_ختم	/* USE_BTMP */
