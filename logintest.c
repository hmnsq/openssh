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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/wait.h>
#అన్తర్భావ <sys/socket.h>

#అన్తర్భావ <netinet/in.h>

#అన్తర్భావ <unistd.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <time.h>

#అన్తర్భావ "loginrec.h"

బాహ్య అక్షరం *__progname;

#నిర్వచించు PAUSE_BEFORE_LOGOUT 3

పూర్ణాంకం nologtest = 0;
పూర్ణాంకం compile_opts_only = 0;
పూర్ణాంకం be_verbose = 0;


/* Dump a logininfo to stdout. Assumes a tab size of 8 chars. */
శూన్య
dump_logininfo(నిర్మాణం logininfo *li, అక్షరం *descname)
{
	/* yes I know how nasty this is */
	రాయి("struct logininfo %s = {\n\t"
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
	    li->pid, li->uid, li->పంక్తి,
	    li->username, li->hostname, li->నిష్క్రమించు,
	    li->termination, li->tv_sec, li->tv_usec,
	    li->hostaddr.sa.sa_family);
}


పూర్ణాంకం
testAPI()
{
	నిర్మాణం logininfo *li1;
	నిర్మాణం passwd *pw;
	నిర్మాణం hostent *he;
	నిర్మాణం sockaddr_in sa_in4;
	అక్షరం cmdstring[256], stripline[8];
	అక్షరం username[32];
#నిర్వచితమైతే HAVE_సమయం_H
	time_t t0, t1, t2, logintime, logouttime;
	అక్షరం s_t0[64],s_t1[64],s_t2[64];
	అక్షరం s_logintime[64], s_logouttime[64]; /* ctime() strings */
#అయితే_ముగింపు

	రాయి("**\n** Testing the API...\n**\n");

	pw = getpwuid(getuid());
	strlcpy(username, pw->pw_name, పరిమాణం(username));

	/* gethostname(hostname, sizeof(hostname)); */

	రాయి("login_alloc_entry test (no host info):\n");

	/* FIXME fake tty more effectively - this could upset some platforms */
	li1 = login_alloc_నమోదు((పూర్ణాంకం)getpid(), username, ఖాళీ, ttyname(0));
	strlcpy(li1->progname, "OpenSSH-logintest", పరిమాణం(li1->progname));

	ఒకవేళ (be_verbose)
		dump_logininfo(li1, "li1");

	రాయి("Setting host address info for 'localhost' (may call out):\n");
	ఒకవేళ (! (he = gethostbyname("localhost"))) {
		రాయి("Couldn't set hostname(lookup failed)\n");
	} లేకపోతే {
		/* NOTE: this is messy, but typically a program wouldn't have to set
		 *  any of this, a sockaddr_in* would be already prepared */
		జ్ఞాపకం_నకలు((శూన్య *)&(sa_in4.sin_addr), (శూన్య *)&(he->h_addr_list[0][0]),
		    పరిమాణం(నిర్మాణం in_addr));
		login_సమితి_addr(li1, (నిర్మాణం sockaddr *) &sa_in4, పరిమాణం(sa_in4));
		strlcpy(li1->hostname, "localhost", పరిమాణం(li1->hostname));
	}
	ఒకవేళ (be_verbose)
		dump_logininfo(li1, "li1");

	ఒకవేళ ((పూర్ణాంకం)geteuid() != 0) {
		రాయి("NOT RUNNING LOGIN TESTS - you are not root!\n");
		తిరిగి 1;
	}

	ఒకవేళ (nologtest)
		తిరిగి 1;

	పంక్తి_stripname(stripline, li1->పంక్తి, పరిమాణం(stripline));

	రాయి("Performing an invalid login attempt (no type field)\n--\n");
	login_write(li1);
	రాయి("--\n(Should have written errors to stderr)\n");

#నిర్వచితమైతే HAVE_సమయం_H
	(శూన్య)time(&t0);
	strlcpy(s_t0, ctime(&t0), పరిమాణం(s_t0));
	t1 = login_get_lastlog_సమయం(getuid());
	strlcpy(s_t1, ctime(&t1), పరిమాణం(s_t1));
	రాయి("Before logging in:\n\tcurrent time is %d - %s\t"
	    "lastlog time is %d - %s\n",
	    (పూర్ణాంకం)t0, s_t0, (పూర్ణాంకం)t1, s_t1);
#అయితే_ముగింపు

	రాయి("Performing a login on line %s ", stripline);
#నిర్వచితమైతే HAVE_సమయం_H
	(శూన్య)time(&logintime);
	strlcpy(s_logintime, ctime(&logintime), పరిమాణం(s_logintime));
	రాయి("at %d - %s", (పూర్ణాంకం)logintime, s_logintime);
#అయితే_ముగింపు
	రాయి("--\n");
	login_login(li1);

	snprintf(cmdstring, పరిమాణం(cmdstring), "who | grep '%s '",
		 stripline);
	system(cmdstring);

	రాయి("--\nPausing for %d second(s)...\n", PAUSE_BEFORE_LOGOUT);
	sleep(PAUSE_BEFORE_LOGOUT);

	రాయి("Performing a logout ");
#నిర్వచితమైతే HAVE_సమయం_H
	(శూన్య)time(&logouttime);
	strlcpy(s_logouttime, ctime(&logouttime), పరిమాణం(s_logouttime));
	రాయి("at %d - %s", (పూర్ణాంకం)logouttime, s_logouttime);
#అయితే_ముగింపు
	రాయి("\nThe root login shown above should be gone.\n"
	    "If the root login hasn't gone, but another user on the same\n"
	    "pty has, this is OK - we're hacking it here, and there\n"
	    "shouldn't be two users on one pty in reality...\n"
	    "-- ('who' output follows)\n");
	login_logout(li1);

	system(cmdstring);
	రాయి("-- ('who' output ends)\n");

#నిర్వచితమైతే HAVE_సమయం_H
	t2 = login_get_lastlog_సమయం(getuid());
	strlcpy(s_t2, ctime(&t2), పరిమాణం(s_t2));
	రాయి("After logging in, lastlog time is %d - %s\n", (పూర్ణాంకం)t2, s_t2);
	ఒకవేళ (t1 == t2)
		రాయి("The lastlog times before and after logging in are the "
		    "same.\nThis indicates that lastlog is ** NOT WORKING "
		    "CORRECTLY **\n");
	లేకపోతే ఒకవేళ (t0 != t2)
		/* We can be off by a second or so, even when recording works fine.
		 * I'm not 100% sure why, but it's true. */
		రాయి("** The login time and the lastlog time differ.\n"
		    "** This indicates that lastlog is either recording the "
		    "wrong time,\n** or retrieving the wrong entry.\n"
		    "If it's off by less than %d second(s) "
		    "run the test again.\n", PAUSE_BEFORE_LOGOUT);
	లేకపోతే
		రాయి("lastlog agrees with the login time. This is a good thing.\n");

#అయితే_ముగింపు

	రాయి("--\nThe output of 'last' shown next should have "
	    "an entry for root \n  on %s for the time shown above:\n--\n",
	    stripline);
	snprintf(cmdstring, పరిమాణం(cmdstring), "last | grep '%s ' | head -3",
		 stripline);
	system(cmdstring);

	రాయి("--\nEnd of login test.\n");

	login_free_నమోదు(li1);

	తిరిగి 1;
} /* testAPI() */


శూన్య
test_పంక్తి_Name(అక్షరం *పంక్తి)
{
	/* have to null-terminate - these functions are designed for
	 * structures with fixed-length char arrays, and don't null-term.*/
	అక్షరం నిండిన[17], strip[9], abbrev[5];

	memset(నిండిన, '\0', పరిమాణం(నిండిన));
	memset(strip, '\0', పరిమాణం(strip));
	memset(abbrev, '\0', పరిమాణం(abbrev));

	పంక్తి_fullname(నిండిన, పంక్తి, పరిమాణం(నిండిన)-1);
	పంక్తి_stripname(strip, నిండిన, పరిమాణం(strip)-1);
	పంక్తి_abbrevname(abbrev, నిండిన, పరిమాణం(abbrev)-1);
	రాయి("%s: %s, %s, %s\n", పంక్తి, నిండిన, strip, abbrev);

} /* testLineName() */


పూర్ణాంకం
testOutput()
{
	రాయి("**\n** Testing linename functions\n**\n");
	test_పంక్తి_Name("/dev/pts/1");
	test_పంక్తి_Name("pts/1");
	test_పంక్తి_Name("pts/999");
	test_పంక్తి_Name("/dev/ttyp00");
	test_పంక్తి_Name("ttyp00");

	తిరిగి 1;
} /* testOutput() */


/* show which options got compiled in */
శూన్య
showOptions(శూన్య)
{
	రాయి("**\n** Compile-time options\n**\n");

	రాయి("login recording methods selected:\n");
#నిర్వచితమైతే USE_LOGIN
	రాయి("\tUSE_LOGIN\n");
#అయితే_ముగింపు
#నిర్వచితమైతే USE_UTMP
	రాయి("\tUSE_UTMP (UTMP_FILE=%s)\n", UTMP_FILE);
#అయితే_ముగింపు
#నిర్వచితమైతే USE_UTMPX
	రాయి("\tUSE_UTMPX\n");
#అయితే_ముగింపు
#నిర్వచితమైతే USE_WTMP
	రాయి("\tUSE_WTMP (WTMP_FILE=%s)\n", WTMP_FILE);
#అయితే_ముగింపు
#నిర్వచితమైతే USE_WTMPX
	రాయి("\tUSE_WTMPX (WTMPX_FILE=%s)\n", WTMPX_FILE);
#అయితే_ముగింపు
#నిర్వచితమైతే USE_LASTLOG
	రాయి("\tUSE_LASTLOG (LASTLOG_FILE=%s)\n", LASTLOG_FILE);
#అయితే_ముగింపు
	రాయి("\n");

} /* showOptions() */


పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం *argv[])
{
	రాయి("Platform-independent login recording test driver\n");

	__progname = ssh_get_progname(argv[0]);
	ఒకవేళ (argc == 2) {
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(argv[1], "-i", 3) == 0)
			compile_opts_only = 1;
		లేకపోతే ఒకవేళ (అక్షరశ్రేణి_పోలిక(argv[1], "-v", 3) == 0)
			be_verbose=1;
	}

	ఒకవేళ (!compile_opts_only) {
		ఒకవేళ (be_verbose && !testOutput())
			తిరిగి 1;

		ఒకవేళ (!testAPI())
			తిరిగి 1;
	}

	showOptions();

	తిరిగి 0;
} /* main() */

