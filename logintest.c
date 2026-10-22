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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/wait.h>
#অন্তর্ভাৱ <sys/socket.h>

#অন্তর্ভাৱ <netinet/in.h>

#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <netdb.h>
#অন্তর্ভাৱ <time.h>

#অন্তর্ভাৱ "loginrec.h"

বাহ্য ৱর্ণ *__progname;

#define PAUSE_BEFORE_LOGOUT 3

পূর্ণাঙ্ক nologtest = 0;
পূর্ণাঙ্ক compile_opts_only = 0;
পূর্ণাঙ্ক be_verbose = 0;


/* Dump a logininfo to stdout. Assumes a tab size of 8 chars. */
শূন্য
dump_logininfo(সংরচনা logininfo *li, ৱর্ণ *descname)
{
	/* yes I know how nasty this is */
	printf("struct logininfo %s = {\n\t"
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
	    li->pid, li->uid, li->সাৰি,
	    li->username, li->hostname, li->exit,
	    li->termination, li->tv_sec, li->tv_usec,
	    li->hostaddr.sa.sa_family);
}


পূর্ণাঙ্ক
testAPI()
{
	সংরচনা logininfo *li1;
	সংরচনা passwd *pw;
	সংরচনা hostent *he;
	সংরচনা sockaddr_in sa_in4;
	ৱর্ণ cmdstring[256], stripline[8];
	ৱর্ণ username[32];
#ifdef HAVE_TIME_H
	time_t t0, t1, t2, logintime, logouttime;
	ৱর্ণ s_t0[64],s_t1[64],s_t2[64];
	ৱর্ণ s_logintime[64], s_logouttime[64]; /* ctime() strings */
#endif

	printf("**\n** Testing the API...\n**\n");

	pw = getpwuid(getuid());
	strlcpy(username, pw->pw_name, পরিমাণ(username));

	/* gethostname(hostname, sizeof(hostname)); */

	printf("login_alloc_entry test (no host info):\n");

	/* FIXME fake tty more effectively - this could upset some platforms */
	li1 = login_alloc_entry((পূর্ণাঙ্ক)getpid(), username, রিক্ত, ttyname(0));
	strlcpy(li1->progname, "OpenSSH-logintest", পরিমাণ(li1->progname));

	যদি (be_verbose)
		dump_logininfo(li1, "li1");

	printf("Setting host address info for 'localhost' (may call out):\n");
	যদি (! (he = gethostbyname("localhost"))) {
		printf("Couldn't set hostname(lookup failed)\n");
	} অন্যথা {
		/* NOTE: this is messy, but typically a program wouldn't have to set
		 *  any of this, a sockaddr_in* would be already prepared */
		memcpy((শূন্য *)&(sa_in4.sin_addr), (শূন্য *)&(he->h_addr_list[0][0]),
		    পরিমাণ(সংরচনা in_addr));
		login_set_addr(li1, (সংরচনা sockaddr *) &sa_in4, পরিমাণ(sa_in4));
		strlcpy(li1->hostname, "localhost", পরিমাণ(li1->hostname));
	}
	যদি (be_verbose)
		dump_logininfo(li1, "li1");

	যদি ((পূর্ণাঙ্ক)geteuid() != 0) {
		printf("NOT RUNNING LOGIN TESTS - you are not root!\n");
		ঘূৰাই 1;
	}

	যদি (nologtest)
		ঘূৰাই 1;

	সাৰি_stripname(stripline, li1->সাৰি, পরিমাণ(stripline));

	printf("Performing an invalid login attempt (no type field)\n--\n");
	login_write(li1);
	printf("--\n(Should have written errors to stderr)\n");

#ifdef HAVE_TIME_H
	(শূন্য)time(&t0);
	strlcpy(s_t0, ctime(&t0), পরিমাণ(s_t0));
	t1 = login_get_lastlog_time(getuid());
	strlcpy(s_t1, ctime(&t1), পরিমাণ(s_t1));
	printf("Before logging in:\n\tcurrent time is %d - %s\t"
	    "lastlog time is %d - %s\n",
	    (পূর্ণাঙ্ক)t0, s_t0, (পূর্ণাঙ্ক)t1, s_t1);
#endif

	printf("Performing a login on line %s ", stripline);
#ifdef HAVE_TIME_H
	(শূন্য)time(&logintime);
	strlcpy(s_logintime, ctime(&logintime), পরিমাণ(s_logintime));
	printf("at %d - %s", (পূর্ণাঙ্ক)logintime, s_logintime);
#endif
	printf("--\n");
	login_login(li1);

	snprintf(cmdstring, পরিমাণ(cmdstring), "who | grep '%s '",
		 stripline);
	system(cmdstring);

	printf("--\nPausing for %d second(s)...\n", PAUSE_BEFORE_LOGOUT);
	sleep(PAUSE_BEFORE_LOGOUT);

	printf("Performing a logout ");
#ifdef HAVE_TIME_H
	(শূন্য)time(&logouttime);
	strlcpy(s_logouttime, ctime(&logouttime), পরিমাণ(s_logouttime));
	printf("at %d - %s", (পূর্ণাঙ্ক)logouttime, s_logouttime);
#endif
	printf("\nThe root login shown above should be gone.\n"
	    "If the root login hasn't gone, but another user on the same\n"
	    "pty has, this is OK - we're hacking it here, and there\n"
	    "shouldn't be two users on one pty in reality...\n"
	    "-- ('who' output follows)\n");
	login_logout(li1);

	system(cmdstring);
	printf("-- ('who' output ends)\n");

#ifdef HAVE_TIME_H
	t2 = login_get_lastlog_time(getuid());
	strlcpy(s_t2, ctime(&t2), পরিমাণ(s_t2));
	printf("After logging in, lastlog time is %d - %s\n", (পূর্ণাঙ্ক)t2, s_t2);
	যদি (t1 == t2)
		printf("The lastlog times before and after logging in are the "
		    "same.\nThis indicates that lastlog is ** NOT WORKING "
		    "CORRECTLY **\n");
	অন্যথা যদি (t0 != t2)
		/* We can be off by a second or so, even when recording works fine.
		 * I'm not 100% sure why, but it's true. */
		printf("** The login time and the lastlog time differ.\n"
		    "** This indicates that lastlog is either recording the "
		    "wrong time,\n** or retrieving the wrong entry.\n"
		    "If it's off by less than %d second(s) "
		    "run the test again.\n", PAUSE_BEFORE_LOGOUT);
	অন্যথা
		printf("lastlog agrees with the login time. This is a good thing.\n");

#endif

	printf("--\nThe output of 'last' shown next should have "
	    "an entry for root \n  on %s for the time shown above:\n--\n",
	    stripline);
	snprintf(cmdstring, পরিমাণ(cmdstring), "last | grep '%s ' | head -3",
		 stripline);
	system(cmdstring);

	printf("--\nEnd of login test.\n");

	login_free_entry(li1);

	ঘূৰাই 1;
} /* testAPI() */


শূন্য
test_সাৰি_Name(ৱর্ণ *সাৰি)
{
	/* have to null-terminate - these functions are designed for
	 * structures with fixed-length char arrays, and don't null-term.*/
	ৱর্ণ full[17], strip[9], abbrev[5];

	memset(full, '\0', পরিমাণ(full));
	memset(strip, '\0', পরিমাণ(strip));
	memset(abbrev, '\0', পরিমাণ(abbrev));

	সাৰি_fullname(full, সাৰি, পরিমাণ(full)-1);
	সাৰি_stripname(strip, full, পরিমাণ(strip)-1);
	সাৰি_abbrevname(abbrev, full, পরিমাণ(abbrev)-1);
	printf("%s: %s, %s, %s\n", সাৰি, full, strip, abbrev);

} /* testLineName() */


পূর্ণাঙ্ক
testOutput()
{
	printf("**\n** Testing linename functions\n**\n");
	test_সাৰি_Name("/dev/pts/1");
	test_সাৰি_Name("pts/1");
	test_সাৰি_Name("pts/999");
	test_সাৰি_Name("/dev/ttyp00");
	test_সাৰি_Name("ttyp00");

	ঘূৰাই 1;
} /* testOutput() */


/* show which options got compiled in */
শূন্য
showOptions(শূন্য)
{
	printf("**\n** Compile-time options\n**\n");

	printf("login recording methods selected:\n");
#ifdef USE_LOGIN
	printf("\tUSE_LOGIN\n");
#endif
#ifdef USE_UTMP
	printf("\tUSE_UTMP (UTMP_FILE=%s)\n", UTMP_FILE);
#endif
#ifdef USE_UTMPX
	printf("\tUSE_UTMPX\n");
#endif
#ifdef USE_WTMP
	printf("\tUSE_WTMP (WTMP_FILE=%s)\n", WTMP_FILE);
#endif
#ifdef USE_WTMPX
	printf("\tUSE_WTMPX (WTMPX_FILE=%s)\n", WTMPX_FILE);
#endif
#ifdef USE_LASTLOG
	printf("\tUSE_LASTLOG (LASTLOG_FILE=%s)\n", LASTLOG_FILE);
#endif
	printf("\n");

} /* showOptions() */


পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, ৱর্ণ *argv[])
{
	printf("Platform-independent login recording test driver\n");

	__progname = ssh_get_progname(argv[0]);
	যদি (argc == 2) {
		যদি (strncmp(argv[1], "-i", 3) == 0)
			compile_opts_only = 1;
		অন্যথা যদি (strncmp(argv[1], "-v", 3) == 0)
			be_verbose=1;
	}

	যদি (!compile_opts_only) {
		যদি (be_verbose && !testOutput())
			ঘূৰাই 1;

		যদি (!testAPI())
			ঘূৰাই 1;
	}

	showOptions();

	ঘূৰাই 0;
} /* main() */

