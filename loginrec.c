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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>
#ضمن <sys/socket.h>
#ضمن <sys/time.h>

#ضمن <netinet/in.h>

#ضمن <stdlib.h>
#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <paths.h>
#ضمن <pwd.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <time.h>
#ضمن <unistd.h>

#ضمن "xmalloc.h"
#ضمن "sshkey.h"
#ضمن "hostfile.h"
#ضمن "ssh.h"
#ضمن "loginrec.h"
#ضمن "log.h"
#ضمن "atomicio.h"
#ضمن "packet.h"
#ضمن "canohost.h"
#ضمن "auth.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "misc.h"

# include <util.h>

#جے_تعریف_شدہ USE_WTMPDB
# include <wtmpdb.h>
#جے_انت

/**
 ** prototypes for helper functions in this file
 **/

#إذا HAVE_UTMP_H
فراغ سیٹ_utmp_ویلا(بنية logininfo *li, بنية utmp *ut);
فراغ construct_utmp(بنية logininfo *li, بنية utmp *ut);
#جے_انت

#جے_تعریف_شدہ HAVE_UTMPX_H
فراغ سیٹ_utmpx_ویلا(بنية logininfo *li, بنية utmpx *ut);
فراغ construct_utmpx(بنية logininfo *li, بنية utmpx *ut);
#جے_انت

صحيح utmp_write_اندراج(بنية logininfo *li);
صحيح utmpx_write_اندراج(بنية logininfo *li);
صحيح wtmp_write_اندراج(بنية logininfo *li);
صحيح wtmpx_write_اندراج(بنية logininfo *li);
صحيح lastlog_write_اندراج(بنية logininfo *li);
صحيح syslogin_write_اندراج(بنية logininfo *li);
#جے_تعریف_شدہ USE_WTMPDB
صحيح wtmpdb_write_اندراج(بنية logininfo *li);
#جے_انت

صحيح getlast_اندراج(بنية logininfo *li);
صحيح lastlog_get_اندراج(بنية logininfo *li);
صحيح utmpx_get_اندراج(بنية logininfo *li);
صحيح wtmp_get_اندراج(بنية logininfo *li);
صحيح wtmpx_get_اندراج(بنية logininfo *li);

خارجي بنية sshbuf *loginmsg;

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
صحيح
login_login(بنية logininfo *li)
{
	li->type = LTYPE_LOGIN;
	أرجع (login_write(li));
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
صحيح
login_logout(بنية logininfo *li)
{
	li->type = LTYPE_LOGOUT;
	أرجع (login_write(li));
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
بنانشانی صحيح
login_get_lastlog_ویلا(ثابت uid_t uid)
{
	بنية logininfo li;

	إذا (login_get_lastlog(&li, uid))
		أرجع (li.tv_sec);
	وإلا
		أرجع (0);
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
بنية logininfo *
login_get_lastlog(بنية logininfo *li, ثابت uid_t uid)
{
	بنية passwd *pw;

	memset(li, '\0', حجم(*li));
	li->uid = uid;

	/*
	 * If we don't have a 'real' lastlog, we need the username to
	 * reliably search wtmp(x) for the last login (see
	 * wtmp_get_entry().)
	 */
	pw = getpwuid(uid);
	إذا (pw == عدم)
		fatal("%s: Cannot find account for uid %ld", __func__,
		    (لما)uid);

	إذا (strlcpy(li->username, pw->pw_name, حجم(li->username)) >=
	    حجم(li->username)) {
		error("%s: username too long (%lu > max %lu)", __func__,
		    (بنانشانی لما)لڑی_لمبائی(pw->pw_name),
		    (بنانشانی لما)حجم(li->username) - 1);
		أرجع عدم;
	}

	إذا (getlast_اندراج(li))
		أرجع (li);
	وإلا
		أرجع (عدم);
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
بنية
logininfo *login_alloc_اندراج(pid_t pid, ثابت حرف *username,
    ثابت حرف *hostname, ثابت حرف *سطر)
{
	بنية logininfo *newli;

	newli = xmalloc(حجم(*newli));
	login_init_اندراج(newli, pid, username, hostname, سطر);
	أرجع (newli);
}


/* login_free_entry(struct logininfo *)    - free struct memory */
فراغ
login_free_اندراج(بنية logininfo *li)
{
	حرر(li);
}


/* login_init_entry(struct logininfo *, int, char*, char*, char*)
 *                                        - initialise a struct logininfo
 *
 * Populates a new struct logininfo, a data structure meant to carry
 * the information required to portably record login info.
 *
 * Returns: 1
 */
صحيح
login_init_اندراج(بنية logininfo *li, pid_t pid, ثابت حرف *username,
    ثابت حرف *hostname, ثابت حرف *سطر)
{
	بنية passwd *pw;

	memset(li, 0, حجم(*li));

	li->pid = pid;

	/* set the line information */
	إذا (سطر)
		سطر_fullname(li->سطر, سطر, حجم(li->سطر));

	إذا (username) {
		strlcpy(li->username, username, حجم(li->username));
		pw = getpwnam(li->username);
		إذا (pw == عدم) {
			fatal("%s: Cannot find user \"%s\"", __func__,
			    li->username);
		}
		li->uid = pw->pw_uid;
	}

	إذا (hostname)
		strlcpy(li->hostname, hostname, حجم(li->hostname));

	أرجع (1);
}

/*
 * login_set_current_time(struct logininfo *)    - set the current time
 *
 * Set the current time in a logininfo structure. This function is
 * meant to eliminate the need to deal with system dependencies for
 * time handling.
 */
فراغ
login_سیٹ_current_ویلا(بنية logininfo *li)
{
	بنية timeval tv;

	gettimeofday(&tv, عدم);

	li->tv_sec = tv.tv_sec;
	li->tv_usec = tv.tv_usec;
}

/* copy a sockaddr_* into our logininfo */
فراغ
login_سیٹ_addr(بنية logininfo *li, ثابت بنية sockaddr *sa,
    ثابت بنانشانی صحيح sa_ناپ)
{
	بنانشانی صحيح bufsize = sa_ناپ;

	/* make sure we don't overrun our union */
	إذا (حجم(li->hostaddr) < sa_ناپ)
		bufsize = حجم(li->hostaddr);

	حافظہ_نقل(&li->hostaddr.sa, sa, bufsize);
}


/**
 ** login_write: Call low-level recording functions based on autoconf
 ** results
 **/
صحيح
login_write(بنية logininfo *li)
{
#جے_بنا_تعریف HAVE_CYGWIN
	إذا (geteuid() != 0) {
		logit("Attempt to write login records by non-root user (aborting)");
		أرجع (1);
	}
#جے_انت

	/* set the timestamp */
	login_سیٹ_current_ویلا(li);
#جے_تعریف_شدہ USE_LOGIN
	syslogin_write_اندراج(li);
#جے_انت
#جے_تعریف_شدہ USE_LASTLOG
	إذا (li->type == LTYPE_LOGIN)
		lastlog_write_اندراج(li);
#جے_انت
#جے_تعریف_شدہ USE_UTMP
	utmp_write_اندراج(li);
#جے_انت
#جے_تعریف_شدہ USE_WTMP
	wtmp_write_اندراج(li);
#جے_انت
#جے_تعریف_شدہ USE_UTMPX
	utmpx_write_اندراج(li);
#جے_انت
#جے_تعریف_شدہ USE_WTMPX
	wtmpx_write_اندراج(li);
#جے_انت
#جے_تعریف_شدہ USE_WTMPDB
	wtmpdb_write_اندراج(li);
#جے_انت
#جے_تعریف_شدہ CUSTOM_SYS_AUTH_ریکارڈ_LOGIN
	إذا (li->type == LTYPE_LOGIN &&
	    !sys_auth_ریکارڈ_login(li->username,li->hostname,li->سطر,
	    loginmsg))
		logit("Writing login record failed for %s", li->username);
#جے_انت
#جے_تعریف_شدہ SSH_AUDIT_EVENTS
	إذا (li->type == LTYPE_LOGIN)
		audit_session_open(li);
	وإلا إذا (li->type == LTYPE_LOGOUT)
		audit_session_close(li);
#جے_انت
	أرجع (0);
}

#جے_تعریف_شدہ LOGIN_NEEDS_UTMPX
صحيح
login_utmp_only(بنية logininfo *li)
{
	li->type = LTYPE_LOGIN;
	login_سیٹ_current_ویلا(li);
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
	أرجع (0);
}
#جے_انت

/**
 ** getlast_entry: Call low-level functions to retrieve the last login
 **                time.
 **/

/* take the uid in li and return the last login time */
صحيح
getlast_اندراج(بنية logininfo *li)
{
#جے_تعریف_شدہ USE_LASTLOG
	أرجع(lastlog_get_اندراج(li));
#وإلا /* !USE_LASTLOG */
#إذا defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
	أرجع (utmpx_get_اندراج(li));
#جے_انت

#إذا defined(DISABLE_LASTLOG)
	/* On some systems we shouldn't even try to obtain last login
	 * time, e.g. AIX */
	أرجع (0);
# elif defined(USE_WTMP) && \
    (defined(HAVE_ویلا_وچ_UTMP) || defined(HAVE_TV_وچ_UTMP))
	/* retrieve last login time from utmp */
	أرجع (wtmp_get_اندراج(li));
# elif defined(USE_WTMPX) && \
    (defined(HAVE_ویلا_وچ_UTMPX) || defined(HAVE_TV_وچ_UTMPX))
	/* If wtmp isn't available, try wtmpx */
	أرجع (wtmpx_get_اندراج(li));
# وإلا
	/* Give up: No means of retrieving last login time */
	أرجع (0);
# endif /* DISABLE_LASTLOG */
#جے_انت /* USE_LASTLOG */
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
	إذا ((لڑی_مقابلہ(src, "/dev/", 5) == 0) || (dstsize < (لڑی_لمبائی(src) + 5)))
		strlcpy(dst, src, dstsize);
	وإلا {
		strlcpy(dst, "/dev/", dstsize);
		strlcat(dst, src, dstsize);
	}
	أرجع (dst);
}

/* line_stripname(): strip the leading '/dev' if it exists, return dst */
حرف *
سطر_stripname(حرف *dst, ثابت حرف *src, صحيح dstsize)
{
	memset(dst, '\0', dstsize);
	إذا (لڑی_مقابلہ(src, "/dev/", 5) == 0)
		strlcpy(dst, src + 5, dstsize);
	وإلا
		strlcpy(dst, src, dstsize);
	أرجع (dst);
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
سطر_abbrevname(حرف *dst, ثابت حرف *src, صحيح dstsize)
{
	ناپ_t len;

	memset(dst, '\0', dstsize);

	إذا (strcmp(src, "ssh:notty") == 0)
		أرجع dst;

	/* Always skip prefix if present */
	إذا (لڑی_مقابلہ(src, "/dev/", 5) == 0)
		src += 5;

#جے_تعریف_شدہ WITH_ABBREV_NO_TTY
	إذا (لڑی_مقابلہ(src, "tty", 3) == 0)
		src += 3;
#جے_انت

	len = لڑی_لمبائی(src);

	إذا (len > 0) {
		إذا (((صحيح)len - dstsize) > 0)
			src +=  ((صحيح)len - dstsize);

		/* note: _don't_ change this to strlcpy */
		strncpy(dst, src, (ناپ_t)dstsize);
	}

	أرجع (dst);
}

/**
 ** utmp utility functions
 **
 ** These functions manipulate struct utmp, taking system differences
 ** into account.
 **/

#إذا defined(USE_BTMP) || defined(USE_UTMP) || defined (USE_WTMP) || defined (USE_LOGIN)

/* build the utmp structure */
فراغ
سیٹ_utmp_ویلا(بنية logininfo *li, بنية utmp *ut)
{
# إذا defined(HAVE_TV_وچ_UTMP)
	ut->ut_tv.tv_sec = li->tv_sec;
	ut->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_ویلا_وچ_UTMP)
	ut->ut_ویلا = li->tv_sec;
# endif
}

فراغ
construct_utmp(بنية logininfo *li,
		    بنية utmp *ut)
{
# ifdef HAVE_ADDR_V6_وچ_UTMP
	بنية sockaddr_in6 *sa6;
# endif

	memset(ut, '\0', حجم(*ut));

	/* First fill out fields used for both logins and logouts */

# ifdef HAVE_ID_وچ_UTMP
	سطر_abbrevname(ut->ut_id, li->سطر, حجم(ut->ut_id));
# endif

# ifdef HAVE_TYPE_وچ_UTMP
	/* This is done here to keep utmp constants out of struct logininfo */
	بدل (li->type) {
	حالة LTYPE_FAILED:
		ut->ut_type = LOGIN_PROCESS;
		اكسر;
	حالة LTYPE_LOGIN:
		ut->ut_type = USER_PROCESS;
		اكسر;
	حالة LTYPE_LOGOUT:
		ut->ut_type = DEAD_PROCESS;
		اكسر;
	}
# endif
	سیٹ_utmp_ویلا(li, ut);

	سطر_stripname(ut->ut_سطر, li->سطر, حجم(ut->ut_سطر));

# ifdef HAVE_PID_وچ_UTMP
	ut->ut_pid = li->pid;
# endif

	/* If we're logging out, leave all other fields blank */
	إذا (li->type == LTYPE_LOGOUT)
		أرجع;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

	/* Use strncpy because we don't necessarily want null termination */
	strncpy(ut->ut_name, li->username,
	    MIN_SIZEOF(ut->ut_name, li->username));
# ifdef HAVE_HOST_وچ_UTMP
	strncpy(ut->ut_host, li->hostname,
	    MIN_SIZEOF(ut->ut_host, li->hostname));
# endif
# ifdef HAVE_ADDR_وچ_UTMP
	/* this is just a 32-bit IP address */
	إذا (li->hostaddr.sa.sa_family == AF_INET)
		ut->ut_addr = li->hostaddr.sa_وچ.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_وچ_UTMP
	/* this is just a 128-bit IPv6 address */
	إذا (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((بنية sockaddr_in6 *)&li->hostaddr.sa);
		حافظہ_نقل(ut->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		إذا (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			ut->ut_addr_v6[0] = ut->ut_addr_v6[3];
			ut->ut_addr_v6[1] = 0;
			ut->ut_addr_v6[2] = 0;
			ut->ut_addr_v6[3] = 0;
		}
	}
# endif
}
#جے_انت /* USE_BTMP || USE_UTMP || USE_WTMP || USE_LOGIN */

/**
 ** utmpx utility functions
 **
 ** These functions manipulate struct utmpx, accounting for system
 ** variations.
 **/

#إذا defined(USE_UTMPX) || defined (USE_WTMPX)
/* build the utmpx structure */
فراغ
سیٹ_utmpx_ویلا(بنية logininfo *li, بنية utmpx *utx)
{
# إذا defined(HAVE_TV_وچ_UTMPX)
	utx->ut_tv.tv_sec = li->tv_sec;
	utx->ut_tv.tv_usec = li->tv_usec;
# elif defined(HAVE_ویلا_وچ_UTMPX)
	utx->ut_ویلا = li->tv_sec;
# endif
}

فراغ
construct_utmpx(بنية logininfo *li, بنية utmpx *utx)
{
# ifdef HAVE_ADDR_V6_وچ_UTMPX
	بنية sockaddr_in6 *sa6;
#  endif
	memset(utx, '\0', حجم(*utx));

# ifdef HAVE_ID_وچ_UTMPX
	سطر_abbrevname(utx->ut_id, li->سطر, حجم(utx->ut_id));
# endif

	/* this is done here to keep utmp constants out of loginrec.h */
	بدل (li->type) {
	حالة LTYPE_LOGIN:
		utx->ut_type = USER_PROCESS;
		اكسر;
	حالة LTYPE_LOGOUT:
		utx->ut_type = DEAD_PROCESS;
		اكسر;
	}
	سطر_stripname(utx->ut_سطر, li->سطر, حجم(utx->ut_سطر));
	سیٹ_utmpx_ویلا(li, utx);
	utx->ut_pid = li->pid;

	/* strncpy(): Don't necessarily want null termination */
	strncpy(utx->ut_user, li->username,
	    MIN_SIZEOF(utx->ut_user, li->username));

	إذا (li->type == LTYPE_LOGOUT)
		أرجع;

	/*
	 * These fields are only used when logging in, and are blank
	 * for logouts.
	 */

# ifdef HAVE_HOST_وچ_UTMPX
	strncpy(utx->ut_host, li->hostname,
	    MIN_SIZEOF(utx->ut_host, li->hostname));
# endif
# ifdef HAVE_SS_وچ_UTMPX
	utx->ut_ss = li->hostaddr.sa_storage;
# endif
# ifdef HAVE_ADDR_وچ_UTMPX
	/* this is just a 32-bit IP address */
	إذا (li->hostaddr.sa.sa_family == AF_INET)
		utx->ut_addr = li->hostaddr.sa_وچ.sin_addr.s_addr;
# endif
# ifdef HAVE_ADDR_V6_وچ_UTMPX
	/* this is just a 128-bit IPv6 address */
	إذا (li->hostaddr.sa.sa_family == AF_INET6) {
		sa6 = ((بنية sockaddr_in6 *)&li->hostaddr.sa);
		حافظہ_نقل(utx->ut_addr_v6, sa6->sin6_addr.s6_addr, 16);
		إذا (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
			utx->ut_addr_v6[0] = utx->ut_addr_v6[3];
			utx->ut_addr_v6[1] = 0;
			utx->ut_addr_v6[2] = 0;
			utx->ut_addr_v6[3] = 0;
		}
	}
# endif
# ifdef HAVE_SYSLEN_وچ_UTMPX
	/* ut_syslen is the length of the utx_host string */
	utx->ut_syslen = MINIMUM(لڑی_لمبائی(li->hostname), حجم(utx->ut_host));
# endif
}
#جے_انت /* USE_UTMPX || USE_WTMPX */

/**
 ** Low-level utmp functions
 **/

/* FIXME: (ATL) utmp_write_direct needs testing */
#جے_تعریف_شدہ USE_UTMP

/* if we can, use pututline() etc. */
# إذا !defined(DISABLE_PUTUTLINE) && defined(HAVE_SETUTENT) && \
	defined(HAVE_PUTUTLINE)
#  define UTMP_USE_LIBRARY
# endif


/* write a utmp entry with the system's help (pututline() and pals) */
# ifdef UTMP_USE_LIBRARY
ساكن صحيح
utmp_write_library(بنية logininfo *li, بنية utmp *ut)
{
	setutent();
	pututline(ut);
#  ifdef HAVE_ENDUTENT
	endutent();
#  endif
	أرجع (1);
}
# وإلا /* UTMP_USE_LIBRARY */

/*
 * Write a utmp entry direct to the file
 * This is a slightly modification of code in OpenBSD's login.c
 */
ساكن صحيح
utmp_write_سدھا(بنية logininfo *li, بنية utmp *ut)
{
	بنية utmp old_ut;
	سجل صحيح fd;
	صحيح tty;

	/* FIXME: (ATL) ttyslot() needs local implementation */

#إذا defined(HAVE_GETTTYENT)
	بنية ttyent *ty;

	tty=0;
	setttyent();
	طالما (عدم != (ty = getttyent())) {
		tty++;
		إذا (!لڑی_مقابلہ(ty->ty_name, ut->ut_سطر, حجم(ut->ut_سطر)))
			اكسر;
	}
	endttyent();

	إذا (عدم == ty) {
		logit_f("tty not found");
		أرجع (0);
	}
#وإلا /* FIXME */

	tty = ttyslot(); /* seems only to work for /dev/ttyp? style names */

#جے_انت /* HAVE_GETTTYENT */

	إذا (tty > 0 && (fd = open(UTMP_FILE, O_RDWR|O_CREAT, 0644)) >= 0) {
		off_t pos, ret;

		pos = (off_t)tty * حجم(بنية utmp);
		إذا ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			أرجع (0);
		}
		إذا (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			أرجع (0);
		}
		/*
		 * Prevent luser from zero'ing out ut_host.
		 * If the new ut_line is empty but the old one is not
		 * and ut_line and ut_name match, preserve the old ut_line.
		 */
		إذا (atomicio(اقرأ, fd, &old_ut, حجم(old_ut)) == حجم(old_ut) &&
		    (ut->ut_host[0] == '\0') && (old_ut.ut_host[0] != '\0') &&
		    (لڑی_مقابلہ(old_ut.ut_سطر, ut->ut_سطر, حجم(ut->ut_سطر)) == 0) &&
		    (لڑی_مقابلہ(old_ut.ut_name, ut->ut_name, حجم(ut->ut_name)) == 0))
			حافظہ_نقل(ut->ut_host, old_ut.ut_host, حجم(ut->ut_host));

		إذا ((ret = lseek(fd, pos, SEEK_SET)) == -1) {
			logit_f("lseek: %s", strerror(errno));
			close(fd);
			أرجع (0);
		}
		إذا (ret != pos) {
			logit("%s: Couldn't seek to tty %d slot in %s",
			    __func__, tty, UTMP_FILE);
			close(fd);
			أرجع (0);
		}
		إذا (atomicio(vwrite, fd, ut, حجم(*ut)) != حجم(*ut)) {
			logit("%s: error writing %s: %s", __func__,
			    UTMP_FILE, strerror(errno));
			close(fd);
			أرجع (0);
		}

		close(fd);
		أرجع (1);
	} وإلا {
		أرجع (0);
	}
}
# endif /* UTMP_USE_LIBRARY */

ساكن صحيح
utmp_perform_login(بنية logininfo *li)
{
	بنية utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	إذا (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		أرجع (0);
	}
# وإلا
	إذا (!utmp_write_سدھا(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		أرجع (0);
	}
# endif
	أرجع (1);
}


ساكن صحيح
utmp_perform_logout(بنية logininfo *li)
{
	بنية utmp ut;

	construct_utmp(li, &ut);
# ifdef UTMP_USE_LIBRARY
	إذا (!utmp_write_library(li, &ut)) {
		logit_f("utmp_write_library() failed");
		أرجع (0);
	}
# وإلا
	إذا (!utmp_write_سدھا(li, &ut)) {
		logit_f("utmp_write_direct() failed");
		أرجع (0);
	}
# endif
	أرجع (1);
}


صحيح
utmp_write_اندراج(بنية logininfo *li)
{
	بدل(li->type) {
	حالة LTYPE_LOGIN:
		أرجع (utmp_perform_login(li));

	حالة LTYPE_LOGOUT:
		أرجع (utmp_perform_logout(li));

	افتراضي:
		logit_f("invalid type field");
		أرجع (0);
	}
}
#جے_انت /* USE_UTMP */


/**
 ** Low-level utmpx functions
 **/

/* not much point if we don't want utmpx entries */
#جے_تعریف_شدہ USE_UTMPX

/* if we have the wherewithal, use pututxline etc. */
# إذا !defined(DISABLE_PUTUTXLINE) && defined(HAVE_SETUTXENT) && \
	defined(HAVE_PUTUTXLINE)
#  define UTMPX_USE_LIBRARY
# endif


/* write a utmpx entry with the system's help (pututxline() and pals) */
# ifdef UTMPX_USE_LIBRARY
ساكن صحيح
utmpx_write_library(بنية logininfo *li, بنية utmpx *utx)
{
	setutxent();
	pututxline(utx);

#  ifdef HAVE_ENDUTXENT
	endutxent();
#  endif
	أرجع (1);
}

# وإلا /* UTMPX_USE_LIBRARY */

/* write a utmp entry direct to the file */
ساكن صحيح
utmpx_write_سدھا(بنية logininfo *li, بنية utmpx *utx)
{
	logit_f("not implemented!");
	أرجع (0);
}
# endif /* UTMPX_USE_LIBRARY */

ساكن صحيح
utmpx_perform_login(بنية logininfo *li)
{
	بنية utmpx utx;

	construct_utmpx(li, &utx);
# ifdef UTMPX_USE_LIBRARY
	إذا (!utmpx_write_library(li, &utx)) {
		logit_f("utmp_write_library() failed");
		أرجع (0);
	}
# وإلا
	إذا (!utmpx_write_سدھا(li, &utx)) {
		logit_f("utmp_write_direct() failed");
		أرجع (0);
	}
# endif
	أرجع (1);
}


ساكن صحيح
utmpx_perform_logout(بنية logininfo *li)
{
	بنية utmpx utx;

	construct_utmpx(li, &utx);
# ifdef HAVE_ID_وچ_UTMPX
	سطر_abbrevname(utx.ut_id, li->سطر, حجم(utx.ut_id));
# endif
# ifdef HAVE_TYPE_وچ_UTMPX
	utx.ut_type = DEAD_PROCESS;
# endif

# ifdef UTMPX_USE_LIBRARY
	utmpx_write_library(li, &utx);
# وإلا
	utmpx_write_سدھا(li, &utx);
# endif
	أرجع (1);
}

صحيح
utmpx_write_اندراج(بنية logininfo *li)
{
	بدل(li->type) {
	حالة LTYPE_LOGIN:
		أرجع (utmpx_perform_login(li));
	حالة LTYPE_LOGOUT:
		أرجع (utmpx_perform_logout(li));
	افتراضي:
		logit_f("invalid type field");
		أرجع (0);
	}
}
#جے_انت /* USE_UTMPX */


/**
 ** Low-level wtmp functions
 **/

#جے_تعریف_شدہ USE_WTMP

/*
 * Write a wtmp entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
ساكن صحيح
wtmp_write(بنية logininfo *li, بنية utmp *ut)
{
	بنية stat buf;
	صحيح fd, ret = 1;

	إذا ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem writing %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		أرجع (0);
	}
	إذا (fstat(fd, &buf) == 0)
		إذا (atomicio(vwrite, fd, ut, حجم(*ut)) != حجم(*ut)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMP_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);
	أرجع (ret);
}

ساكن صحيح
wtmp_perform_login(بنية logininfo *li)
{
	بنية utmp ut;

	construct_utmp(li, &ut);
	أرجع (wtmp_write(li, &ut));
}


ساكن صحيح
wtmp_perform_logout(بنية logininfo *li)
{
	بنية utmp ut;

	construct_utmp(li, &ut);
	أرجع (wtmp_write(li, &ut));
}


صحيح
wtmp_write_اندراج(بنية logininfo *li)
{
	بدل(li->type) {
	حالة LTYPE_LOGIN:
		أرجع (wtmp_perform_login(li));
	حالة LTYPE_LOGOUT:
		أرجع (wtmp_perform_logout(li));
	افتراضي:
		logit_f("invalid type field");
		أرجع (0);
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
ساكن صحيح
wtmp_islogin(بنية logininfo *li, بنية utmp *ut)
{
	إذا (لڑی_مقابلہ(li->username, ut->ut_name,
	    MIN_SIZEOF(li->username, ut->ut_name)) == 0) {
# ifdef HAVE_TYPE_وچ_UTMP
		إذا (ut->ut_type & USER_PROCESS)
			أرجع (1);
# وإلا
		أرجع (1);
# endif
	}
	أرجع (0);
}

صحيح
wtmp_get_اندراج(بنية logininfo *li)
{
	بنية stat st;
	بنية utmp ut;
	صحيح fd, لبھیا = 0;

	/* Clear the time entries in our logininfo */
	li->tv_sec = li->tv_usec = 0;

	إذا ((fd = open(WTMP_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		أرجع (0);
	}
	إذا (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMP_FILE, strerror(errno));
		close(fd);
		أرجع (0);
	}

	/* Seek to the start of the last struct utmp */
	إذا (lseek(fd, -(off_t)حجم(بنية utmp), SEEK_END) == -1) {
		/* Looks like we've got a fresh wtmp file */
		close(fd);
		أرجع (0);
	}

	طالما (!لبھیا) {
		إذا (atomicio(اقرأ, fd, &ut, حجم(ut)) != حجم(ut)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMP_FILE, strerror(errno));
			close (fd);
			أرجع (0);
		}
		إذا (wtmp_islogin(li, &ut) ) {
			لبھیا = 1;
			/*
			 * We've already checked for a time in struct
			 * utmp, in login_getlast()
			 */
# ifdef HAVE_ویلا_وچ_UTMP
			li->tv_sec = ut.ut_ویلا;
# وإلا
#  إذا HAVE_TV_وچ_UTMP
			li->tv_sec = ut.ut_tv.tv_sec;
#  endif
# endif
			سطر_fullname(li->سطر, ut.ut_سطر,
			    MIN_SIZEOF(li->سطر, ut.ut_سطر));
# ifdef HAVE_HOST_وچ_UTMP
			strlcpy(li->hostname, ut.ut_host,
			    MIN_SIZEOF(li->hostname, ut.ut_host));
# endif
			استمر;
		}
		/* Seek back 2 x struct utmp */
		إذا (lseek(fd, -(off_t)(2 * حجم(بنية utmp)), SEEK_CUR) == -1) {
			/* We've found the start of the file, so quit */
			close(fd);
			أرجع (0);
		}
	}

	/* We found an entry. Tidy up and return */
	close(fd);
	أرجع (1);
}
# endif /* USE_WTMP */


/**
 ** Low-level wtmpx functions
 **/

#جے_تعریف_شدہ USE_WTMPX
/*
 * Write a wtmpx entry direct to the end of the file
 * This is a slight modification of code in OpenBSD's logwtmp.c
 */
ساكن صحيح
wtmpx_write(بنية logininfo *li, بنية utmpx *utx)
{
#جے_بنا_تعریف HAVE_UPDWTMPX
	بنية stat buf;
	صحيح fd, ret = 1;

	إذا ((fd = open(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		أرجع (0);
	}

	إذا (fstat(fd, &buf) == 0)
		إذا (atomicio(vwrite, fd, utx, حجم(*utx)) != حجم(*utx)) {
			ftruncate(fd, buf.st_size);
			logit("%s: problem writing %s: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			ret = 0;
		}
	close(fd);

	أرجع (ret);
#وإلا
	updwtmpx(WTMPX_FILE, utx);
	أرجع (1);
#جے_انت
}


ساكن صحيح
wtmpx_perform_login(بنية logininfo *li)
{
	بنية utmpx utx;

	construct_utmpx(li, &utx);
	أرجع (wtmpx_write(li, &utx));
}


ساكن صحيح
wtmpx_perform_logout(بنية logininfo *li)
{
	بنية utmpx utx;

	construct_utmpx(li, &utx);
	أرجع (wtmpx_write(li, &utx));
}


صحيح
wtmpx_write_اندراج(بنية logininfo *li)
{
	بدل(li->type) {
	حالة LTYPE_LOGIN:
		أرجع (wtmpx_perform_login(li));
	حالة LTYPE_LOGOUT:
		أرجع (wtmpx_perform_logout(li));
	افتراضي:
		logit_f("invalid type field");
		أرجع (0);
	}
}

/* Please see the notes above wtmp_islogin() for information about the
   next two functions */

/* Return true if this wtmpx entry indicates a login */
ساكن صحيح
wtmpx_islogin(بنية logininfo *li, بنية utmpx *utx)
{
	إذا (لڑی_مقابلہ(li->username, utx->ut_user,
	    MIN_SIZEOF(li->username, utx->ut_user)) == 0 ) {
# ifdef HAVE_TYPE_وچ_UTMPX
		إذا (utx->ut_type == USER_PROCESS)
			أرجع (1);
# وإلا
		أرجع (1);
# endif
	}
	أرجع (0);
}


صحيح
wtmpx_get_اندراج(بنية logininfo *li)
{
	بنية stat st;
	بنية utmpx utx;
	صحيح fd, لبھیا=0;

	/* Clear the time entries */
	li->tv_sec = li->tv_usec = 0;

	إذا ((fd = open(WTMPX_FILE, O_RDONLY)) < 0) {
		logit("%s: problem opening %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		أرجع (0);
	}
	إذا (fstat(fd, &st) != 0) {
		logit("%s: couldn't stat %s: %s", __func__,
		    WTMPX_FILE, strerror(errno));
		close(fd);
		أرجع (0);
	}

	/* Seek to the start of the last struct utmpx */
	إذا (lseek(fd, -(off_t)حجم(بنية utmpx), SEEK_END) == -1 ) {
		/* probably a newly rotated wtmpx file */
		close(fd);
		أرجع (0);
	}

	طالما (!لبھیا) {
		إذا (atomicio(اقرأ, fd, &utx, حجم(utx)) != حجم(utx)) {
			logit("%s: read of %s failed: %s", __func__,
			    WTMPX_FILE, strerror(errno));
			close (fd);
			أرجع (0);
		}
		/*
		 * Logouts are recorded as a blank username on a particular
		 * line. So, we just need to find the username in struct utmpx
		 */
		إذا (wtmpx_islogin(li, &utx)) {
			لبھیا = 1;
# إذا defined(HAVE_TV_وچ_UTMPX)
			li->tv_sec = utx.ut_tv.tv_sec;
# elif defined(HAVE_ویلا_وچ_UTMPX)
			li->tv_sec = utx.ut_ویلا;
# endif
			سطر_fullname(li->سطر, utx.ut_سطر, حجم(li->سطر));
# إذا defined(HAVE_HOST_وچ_UTMPX)
			strlcpy(li->hostname, utx.ut_host,
			    MIN_SIZEOF(li->hostname, utx.ut_host));
# endif
			استمر;
		}
		إذا (lseek(fd, -(off_t)(2 * حجم(بنية utmpx)), SEEK_CUR) == -1) {
			close(fd);
			أرجع (0);
		}
	}

	close(fd);
	أرجع (1);
}
#جے_انت /* USE_WTMPX */

#جے_تعریف_شدہ USE_WTMPDB
ساكن صحيح
wtmpdb_perform_login(بنية logininfo *li)
{
	uint64_t login_ویلا = li->tv_sec * ((uint64_t) 1000000ULL) +
	    li->tv_usec;
	ثابت حرف *tty;

	إذا (لڑی_مقابلہ(li->سطر, "/dev/", 5) == 0)
		tty = &(li->سطر[5]);
	وإلا
		tty = li->سطر;

	li->wtmpdb_id = wtmpdb_login(عدم, USER_PROCESS, li->username,
	    login_ویلا, tty, li->hostname, 0, 0);

	إذا (li->wtmpdb_id < 0)
		أرجع (0);

	أرجع (1);
}

ساكن صحيح
wtmpdb_perform_logout(بنية logininfo *li)
{
	uint64_t logout_ویلا = li->tv_sec * ((uint64_t) 1000000ULL) +
	   li->tv_usec;

	إذا (li->wtmpdb_id == 0) {
		ثابت حرف *tty;

		إذا (لڑی_مقابلہ(li->سطر, "/dev/", 5) == 0)
			tty = &(li->سطر[5]);
		وإلا
			tty = li->سطر;

		li->wtmpdb_id = wtmpdb_get_id(عدم, tty, عدم);
	}
	wtmpdb_logout(عدم, li->wtmpdb_id, logout_ویلا, عدم);

	أرجع (1);
}

صحيح
wtmpdb_write_اندراج(بنية logininfo *li)
{
	بدل(li->type) {
	حالة LTYPE_LOGIN:
		أرجع (wtmpdb_perform_login(li));
	حالة LTYPE_LOGOUT:
		أرجع (wtmpdb_perform_logout(li));
	افتراضي:
		logit_f("invalid type field");
		أرجع (0);
	}
}
#جے_انت

/**
 ** Low-level libutil login() functions
 **/

#جے_تعریف_شدہ USE_LOGIN
ساكن صحيح
syslogin_perform_login(بنية logininfo *li)
{
	بنية utmp *ut;

	ut = xmalloc(حجم(*ut));
	construct_utmp(li, ut);
	login(ut);
	حرر(ut);

	أرجع (1);
}

ساكن صحيح
syslogin_perform_logout(بنية logininfo *li)
{
# ifdef HAVE_LOGOUT
	حرف سطر[UT_LINESIZE];

	(فراغ)سطر_stripname(سطر, li->سطر, حجم(سطر));

	إذا (!logout(سطر))
		logit_f("logout() returned an error");
#  ifdef HAVE_LOGWTMP
	وإلا
		logwtmp(سطر, "", "");
#  endif
	/* FIXME: (ATL - if the need arises) What to do if we have
	 * login, but no logout?  what if logout but no logwtmp? All
	 * routines are in libutil so they should all be there,
	 * but... */
# endif
	أرجع (1);
}

صحيح
syslogin_write_اندراج(بنية logininfo *li)
{
	بدل (li->type) {
	حالة LTYPE_LOGIN:
		أرجع (syslogin_perform_login(li));
	حالة LTYPE_LOGOUT:
		أرجع (syslogin_perform_logout(li));
	افتراضي:
		logit_f("Invalid type field");
		أرجع (0);
	}
}
#جے_انت /* USE_LOGIN */

/* end of file log-syslogin.c */

/**
 ** Low-level lastlog functions
 **/

#جے_تعریف_شدہ USE_LASTLOG

#إذا !defined(LASTLOG_WRITE_PUTUTXLINE) || !defined(HAVE_GETLASTLOGXBYNAME)
/* open the file (using filemode) and seek to the login entry */
ساكن صحيح
lastlog_openseek(بنية logininfo *li, صحيح *fd, صحيح filemode)
{
	off_t وتھ;
	حرف lastlog_file[1024];
	بنية stat st;

	إذا (stat(LASTLOG_FILE, &st) != 0) {
		logit("%s: Couldn't stat %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		أرجع (0);
	}
	إذا (S_ISDIR(st.st_mode)) {
		snprintf(lastlog_file, حجم(lastlog_file), "%s/%s",
		    LASTLOG_FILE, li->username);
	} وإلا إذا (S_ISREG(st.st_mode)) {
		strlcpy(lastlog_file, LASTLOG_FILE, حجم(lastlog_file));
	} وإلا {
		logit("%s: %.100s is not a file or directory!", __func__,
		    LASTLOG_FILE);
		أرجع (0);
	}

	*fd = open(lastlog_file, filemode, 0600);
	إذا (*fd < 0) {
		debug("%s: Couldn't open %s: %s", __func__,
		    lastlog_file, strerror(errno));
		أرجع (0);
	}

	إذا (S_ISREG(st.st_mode)) {
		/* find this uid's offset in the lastlog file */
		وتھ = (off_t) ((u_long)li->uid * حجم(بنية lastlog));

		إذا (lseek(*fd, وتھ, SEEK_SET) != وتھ) {
			logit("%s: %s->lseek(): %s", __func__,
			    lastlog_file, strerror(errno));
			close(*fd);
			أرجع (0);
		}
	}

	أرجع (1);
}
#جے_انت /* !LASTLOG_WRITE_PUTUTXLINE || !HAVE_GETLASTLOGXBYNAME */

#جے_تعریف_شدہ LASTLOG_WRITE_PUTUTXLINE
صحيح
lastlog_write_اندراج(بنية logininfo *li)
{
	بدل(li->type) {
	حالة LTYPE_LOGIN:
		أرجع 1; /* lastlog written by pututxline */
	افتراضي:
		logit("lastlog_write_entry: Invalid type field");
		أرجع 0;
	}
}
#وإلا /* LASTLOG_WRITE_PUTUTXLINE */
صحيح
lastlog_write_اندراج(بنية logininfo *li)
{
	بنية lastlog آخری;
	صحيح fd;

	بدل(li->type) {
	حالة LTYPE_LOGIN:
		/* create our struct lastlog */
		memset(&آخری, '\0', حجم(آخری));
		سطر_stripname(آخری.ll_سطر, li->سطر, حجم(آخری.ll_سطر));
		strlcpy(آخری.ll_host, li->hostname,
		    MIN_SIZEOF(آخری.ll_host, li->hostname));
		آخری.ll_ویلا = li->tv_sec;

		إذا (!lastlog_openseek(li, &fd, O_RDWR|O_CREAT))
			أرجع (0);

		/* write the entry */
		إذا (atomicio(vwrite, fd, &آخری, حجم(آخری)) != حجم(آخری)) {
			close(fd);
			logit("%s: Error writing to %s: %s", __func__,
			    LASTLOG_FILE, strerror(errno));
			أرجع (0);
		}

		close(fd);
		أرجع (1);
	افتراضي:
		logit_f("Invalid type field");
		أرجع (0);
	}
}
#جے_انت /* LASTLOG_WRITE_PUTUTXLINE */

#جے_تعریف_شدہ HAVE_GETLASTLOGXBYNAME
صحيح
lastlog_get_اندراج(بنية logininfo *li)
{
	بنية lastlogx l, *ll;

	إذا ((ll = getlastlogxbyname(li->username, &l)) == عدم) {
		memset(&l, '\0', حجم(l));
		ll = &l;
	}
	سطر_fullname(li->سطر, ll->ll_سطر, حجم(li->سطر));
	strlcpy(li->hostname, ll->ll_host,
		MIN_SIZEOF(li->hostname, ll->ll_host));
	li->tv_sec = ll->ll_tv.tv_sec;
	li->tv_usec = ll->ll_tv.tv_usec;
	أرجع (1);
}
#وإلا /* HAVE_GETLASTLOGXBYNAME */
صحيح
lastlog_get_اندراج(بنية logininfo *li)
{
	بنية lastlog آخری;
	صحيح fd, ret;

	إذا (!lastlog_openseek(li, &fd, O_RDONLY))
		أرجع (0);

	ret = atomicio(اقرأ, fd, &آخری, حجم(آخری));
	close(fd);

	بدل (ret) {
	حالة 0:
		memset(&آخری, '\0', حجم(آخری));
		/* FALLTHRU */
	حالة حجم(آخری):
		سطر_fullname(li->سطر, آخری.ll_سطر, حجم(li->سطر));
		strlcpy(li->hostname, آخری.ll_host,
		    MIN_SIZEOF(li->hostname, آخری.ll_host));
		li->tv_sec = آخری.ll_ویلا;
		أرجع (1);
	حالة -1:
		error("%s: Error reading from %s: %s", __func__,
		    LASTLOG_FILE, strerror(errno));
		أرجع (0);
	افتراضي:
		error("%s: Error reading from %s: Expecting %d, got %d",
		    __func__, LASTLOG_FILE, (صحيح)حجم(آخری), ret);
		أرجع (0);
	}

	/* NOTREACHED */
	أرجع (0);
}
#جے_انت /* HAVE_GETLASTLOGXBYNAME */
#جے_انت /* USE_LASTLOG */

#إذا defined(USE_UTMPX) && defined(HAVE_SETUTXDB) && \
    defined(UTXDB_LASTLOGIN) && defined(HAVE_GETUTXUSER)
صحيح
utmpx_get_اندراج(بنية logininfo *li)
{
	بنية utmpx *utx;

	إذا (setutxdb(UTXDB_LASTLOGIN, عدم) != 0)
		أرجع (0);
	utx = getutxuser(li->username);
	إذا (utx == عدم) {
		endutxent();
		أرجع (0);
	}

	سطر_fullname(li->سطر, utx->ut_سطر,
	    MIN_SIZEOF(li->سطر, utx->ut_سطر));
	strlcpy(li->hostname, utx->ut_host,
	    MIN_SIZEOF(li->hostname, utx->ut_host));
	li->tv_sec = utx->ut_tv.tv_sec;
	li->tv_usec = utx->ut_tv.tv_usec;
	endutxent();
	أرجع (1);
}
#جے_انت /* USE_UTMPX && HAVE_SETUTXDB && UTXDB_LASTLOGIN && HAVE_GETUTXUSER */

#جے_تعریف_شدہ USE_BTMP
/*
 * Logs failed login attempts in _PATH_BTMP if that exists.
 * The most common login failure is to give password instead of username.
 * So the _PATH_BTMP file is checked for the correct permission, so that only
 * root can read it.
 */
فراغ
ریکارڈ_failed_login(بنية ssh *ssh, ثابت حرف *username, ثابت حرف *hostname,
    ثابت حرف *ttyn)
{
	صحيح fd;
	بنية utmp ut;
	بنية logininfo li;
	socklen_t fromlen = حجم(li.hostaddr);
	time_t t;
	بنية stat fst;

	إذا (geteuid() != 0)
		أرجع;
	إذا ((fd = open(رستہ_BTMP, O_WRONLY | O_APPEND)) < 0) {
		debug("Unable to open the btmp file %s: %s", رستہ_BTMP,
		    strerror(errno));
		أرجع;
	}
	إذا (fstat(fd, &fst) < 0) {
		logit("%s: fstat of %s failed: %s", __func__, رستہ_BTMP,
		    strerror(errno));
		اذهب باہرلا;
	}
	إذا ((fst.st_mode & (S_IXGRP | S_IRWXO)) || fst.st_uid != 0) {
		logit("Excess permission or bad ownership on file %s",
		    رستہ_BTMP);
		اذهب باہرلا;
	}

	/* Construct a logininfo and turn it into a utmp */
	memset(&li, 0, حجم(li));
	li.type = LTYPE_FAILED;
	li.pid = getpid();
	strlcpy(li.سطر, "ssh:notty", حجم(li.سطر));
	strlcpy(li.username, username, حجم(li.username));
	strlcpy(li.hostname, hostname, حجم(li.hostname));
	time(&t);
	li.tv_sec = t > 0 ? (بنانشانی لما)t : 0;
	إذا (ssh_packet_connection_is_on_socket(ssh)) {
		(فراغ)getpeername(ssh_packet_get_connection_وچ(ssh),
		    &li.hostaddr.sa, &fromlen);
	}
	construct_utmp(&li, &ut);

	إذا (atomicio(vwrite, fd, &ut, حجم(ut)) != حجم(ut)) {
		error("Failed to write to %s: %s", رستہ_BTMP,
		    strerror(errno));
	}
باہرلا:
	close(fd);
}
#جے_انت	/* USE_BTMP */
