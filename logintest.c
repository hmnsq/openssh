/*
 * Copyright (c) 2000 Andre Lucas.  All rights reserved.
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
 ** logintest.c:  simple test driver for platform-independent login recording
 **               and lastlog retrieval
 **/

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/wait.h>
#ضمن <sys/socket.h>

#ضمن <netinet/in.h>

#ضمن <unistd.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <pwd.h>
#ضمن <netdb.h>
#ضمن <time.h>

#ضمن "loginrec.h"

خارجي حرف *__progname;

#تعریف_کړه PAUSE_BEFORE_LOGOUT 3

صحيح nologtest = 0;
صحيح compile_opts_only = 0;
صحيح be_verbose = 0;


/* Dump a logininfo to stdout. Assumes a tab size of 8 chars. */
فراغ
dump_logininfo(بنية logininfo *li, حرف *descname)
{
	/* yes I know how nasty this is */
	چاپ_کړه("struct logininfo %s = {\n\t"
	    "progname\t'%s'\n\ttype\t\t%d\n\t"
	    "pid\t\t%d\n\tuid\t\t%d\n\t"
	    "line\t\t'%s'\n\tusername\t'%s'\n\t"
	    "hostname\t'%s'\n\texit\t\t%d\n\ttermination\t%d\n\t"
	    "tv_sec\t%d\n\ttv_usec\t%d\n\t"
	    "struct login_netinfo hostaddr {\n\t\t"
	    "struct sockaddr sa {\n"
	    "\t\t\tfamily\t%d\n\t\t}\n"
	    "\t}\n"
	    "}\n",
	    descname, li->progname, li->type,
	    li->pid, li->uid, li->کرښه,
	    li->username, li->hostname, li->وتل,
	    li->termination, li->tv_sec, li->tv_usec,
	    li->hostaddr.sa.sa_family);
}


صحيح
testAPI()
{
	بنية logininfo *li1;
	بنية passwd *pw;
	بنية hostent *he;
	بنية sockaddr_in sa_in4;
	حرف cmdstring[256], stripline[8];
	حرف username[32];
#که_تعریف_شوی HAVE_وخت_H
	time_t t0, t1, t2, logintime, logouttime;
	حرف s_t0[64],s_t1[64],s_t2[64];
	حرف s_logintime[64], s_logouttime[64]; /* ctime() strings */
#د_که_پای

	چاپ_کړه("**\n** Testing the API...\n**\n");

	pw = getpwuid(getuid());
	strlcpy(username, pw->pw_name, حجم(username));

	/* gethostname(hostname, sizeof(hostname)); */

	چاپ_کړه("login_alloc_entry test (no host info):\n");

	/* FIXME fake tty more effectively - this could upset some platforms */
	li1 = login_alloc_ثبت((صحيح)getpid(), username, عدم, ttyname(0));
	strlcpy(li1->progname, "OpenSSH-logintest", حجم(li1->progname));

	إذا (be_verbose)
		dump_logininfo(li1, "li1");

	چاپ_کړه("Setting host address info for 'localhost' (may call out):\n");
	إذا (! (he = gethostbyname("localhost"))) {
		چاپ_کړه("Couldn't set hostname(lookup failed)\n");
	} وإلا {
		/* NOTE: this is messy, but typically a program wouldn't have to set
		 *  any of this, a sockaddr_in* would be already prepared */
		حافظه_نقل((فراغ *)&(sa_in4.sin_addr), (فراغ *)&(he->h_addr_list[0][0]),
		    حجم(بنية in_addr));
		login_سېټ_addr(li1, (بنية sockaddr *) &sa_in4, حجم(sa_in4));
		strlcpy(li1->hostname, "localhost", حجم(li1->hostname));
	}
	إذا (be_verbose)
		dump_logininfo(li1, "li1");

	إذا ((صحيح)geteuid() != 0) {
		چاپ_کړه("NOT RUNNING LOGIN TESTS - you are not root!\n");
		أرجع 1;
	}

	إذا (nologtest)
		أرجع 1;

	کرښه_stripname(stripline, li1->کرښه, حجم(stripline));

	چاپ_کړه("Performing an invalid login attempt (no type field)\n--\n");
	login_write(li1);
	چاپ_کړه("--\n(Should have written errors to stderr)\n");

#که_تعریف_شوی HAVE_وخت_H
	(فراغ)time(&t0);
	strlcpy(s_t0, ctime(&t0), حجم(s_t0));
	t1 = login_get_lastlog_وخت(getuid());
	strlcpy(s_t1, ctime(&t1), حجم(s_t1));
	چاپ_کړه("Before logging in:\n\tcurrent time is %d - %s\t"
	    "lastlog time is %d - %s\n",
	    (صحيح)t0, s_t0, (صحيح)t1, s_t1);
#د_که_پای

	چاپ_کړه("Performing a login on line %s ", stripline);
#که_تعریف_شوی HAVE_وخت_H
	(فراغ)time(&logintime);
	strlcpy(s_logintime, ctime(&logintime), حجم(s_logintime));
	چاپ_کړه("at %d - %s", (صحيح)logintime, s_logintime);
#د_که_پای
	چاپ_کړه("--\n");
	login_login(li1);

	snprintf(cmdstring, حجم(cmdstring), "who | grep '%s '",
		 stripline);
	system(cmdstring);

	چاپ_کړه("--\nPausing for %d second(s)...\n", PAUSE_BEFORE_LOGOUT);
	sleep(PAUSE_BEFORE_LOGOUT);

	چاپ_کړه("Performing a logout ");
#که_تعریف_شوی HAVE_وخت_H
	(فراغ)time(&logouttime);
	strlcpy(s_logouttime, ctime(&logouttime), حجم(s_logouttime));
	چاپ_کړه("at %d - %s", (صحيح)logouttime, s_logouttime);
#د_که_پای
	چاپ_کړه("\nThe root login shown above should be gone.\n"
	    "If the root login hasn't gone, but another user on the same\n"
	    "pty has, this is OK - we're hacking it here, and there\n"
	    "shouldn't be two users on one pty in reality...\n"
	    "-- ('who' output follows)\n");
	login_logout(li1);

	system(cmdstring);
	چاپ_کړه("-- ('who' output ends)\n");

#که_تعریف_شوی HAVE_وخت_H
	t2 = login_get_lastlog_وخت(getuid());
	strlcpy(s_t2, ctime(&t2), حجم(s_t2));
	چاپ_کړه("After logging in, lastlog time is %d - %s\n", (صحيح)t2, s_t2);
	إذا (t1 == t2)
		چاپ_کړه("The lastlog times before and after logging in are the "
		    "same.\nThis indicates that lastlog is ** NOT WORKING "
		    "CORRECTLY **\n");
	وإلا إذا (t0 != t2)
		/* We can be off by a second or so, even when recording works fine.
		 * I'm not 100% sure why, but it's true. */
		چاپ_کړه("** The login time and the lastlog time differ.\n"
		    "** This indicates that lastlog is either recording the "
		    "wrong time,\n** or retrieving the wrong entry.\n"
		    "If it's off by less than %d second(s) "
		    "run the test again.\n", PAUSE_BEFORE_LOGOUT);
	وإلا
		چاپ_کړه("lastlog agrees with the login time. This is a good thing.\n");

#د_که_پای

	چاپ_کړه("--\nThe output of 'last' shown next should have "
	    "an entry for root \n  on %s for the time shown above:\n--\n",
	    stripline);
	snprintf(cmdstring, حجم(cmdstring), "last | grep '%s ' | head -3",
		 stripline);
	system(cmdstring);

	چاپ_کړه("--\nEnd of login test.\n");

	login_free_ثبت(li1);

	أرجع 1;
} /* testAPI() */


فراغ
test_کرښه_Name(حرف *کرښه)
{
	/* have to null-terminate - these functions are designed for
	 * structures with fixed-length char arrays, and don't null-term.*/
	حرف ډک[17], strip[9], abbrev[5];

	memset(ډک, '\0', حجم(ډک));
	memset(strip, '\0', حجم(strip));
	memset(abbrev, '\0', حجم(abbrev));

	کرښه_fullname(ډک, کرښه, حجم(ډک)-1);
	کرښه_stripname(strip, ډک, حجم(strip)-1);
	کرښه_abbrevname(abbrev, ډک, حجم(abbrev)-1);
	چاپ_کړه("%s: %s, %s, %s\n", کرښه, ډک, strip, abbrev);

} /* testLineName() */


صحيح
testOutput()
{
	چاپ_کړه("**\n** Testing linename functions\n**\n");
	test_کرښه_Name("/dev/pts/1");
	test_کرښه_Name("pts/1");
	test_کرښه_Name("pts/999");
	test_کرښه_Name("/dev/ttyp00");
	test_کرښه_Name("ttyp00");

	أرجع 1;
} /* testOutput() */


/* show which options got compiled in */
فراغ
showOptions(فراغ)
{
	چاپ_کړه("**\n** Compile-time options\n**\n");

	چاپ_کړه("login recording methods selected:\n");
#که_تعریف_شوی USE_LOGIN
	چاپ_کړه("\tUSE_LOGIN\n");
#د_که_پای
#که_تعریف_شوی USE_UTMP
	چاپ_کړه("\tUSE_UTMP (UTMP_FILE=%s)\n", UTMP_FILE);
#د_که_پای
#که_تعریف_شوی USE_UTMPX
	چاپ_کړه("\tUSE_UTMPX\n");
#د_که_پای
#که_تعریف_شوی USE_WTMP
	چاپ_کړه("\tUSE_WTMP (WTMP_FILE=%s)\n", WTMP_FILE);
#د_که_پای
#که_تعریف_شوی USE_WTMPX
	چاپ_کړه("\tUSE_WTMPX (WTMPX_FILE=%s)\n", WTMPX_FILE);
#د_که_پای
#که_تعریف_شوی USE_LASTLOG
	چاپ_کړه("\tUSE_LASTLOG (LASTLOG_FILE=%s)\n", LASTLOG_FILE);
#د_که_پای
	چاپ_کړه("\n");

} /* showOptions() */


صحيح
اصلي(صحيح argc, حرف *argv[])
{
	چاپ_کړه("Platform-independent login recording test driver\n");

	__progname = ssh_get_progname(argv[0]);
	إذا (argc == 2) {
		إذا (مزي_پرتله(argv[1], "-i", 3) == 0)
			compile_opts_only = 1;
		وإلا إذا (مزي_پرتله(argv[1], "-v", 3) == 0)
			be_verbose=1;
	}

	إذا (!compile_opts_only) {
		إذا (be_verbose && !testOutput())
			أرجع 1;

		إذا (!testAPI())
			أرجع 1;
	}

	showOptions();

	أرجع 0;
} /* main() */

