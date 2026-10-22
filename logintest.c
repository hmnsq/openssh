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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>

#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <time.h>

#ଅନ୍ତର୍ଭାଵ "loginrec.h"

ବାହ୍ୟ ଅକ୍ଷର *__progname;

#define PAUSE_BEFORE_LOGOUT 3

ପୂର୍ଣ୍ଣସଂଖ୍ୟା nologtest = 0;
ପୂର୍ଣ୍ଣସଂଖ୍ୟା compile_opts_only = 0;
ପୂର୍ଣ୍ଣସଂଖ୍ୟା be_verbose = 0;


/* Dump a logininfo to stdout. Assumes a tab size of 8 chars. */
ଶୂନ୍ୟ
dump_logininfo(ସଂରଚନା logininfo *li, ଅକ୍ଷର *descname)
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
	    li->pid, li->uid, li->ଧାଡ଼ି,
	    li->username, li->hostname, li->exit,
	    li->termination, li->tv_sec, li->tv_usec,
	    li->hostaddr.sa.sa_family);
}


ପୂର୍ଣ୍ଣସଂଖ୍ୟା
testAPI()
{
	ସଂରଚନା logininfo *li1;
	ସଂରଚନା passwd *pw;
	ସଂରଚନା hostent *he;
	ସଂରଚନା sockaddr_in sa_in4;
	ଅକ୍ଷର cmdstring[256], stripline[8];
	ଅକ୍ଷର username[32];
#ifdef HAVE_TIME_H
	time_t t0, t1, t2, logintime, logouttime;
	ଅକ୍ଷର s_t0[64],s_t1[64],s_t2[64];
	ଅକ୍ଷର s_logintime[64], s_logouttime[64]; /* ctime() strings */
#endif

	printf("**\n** Testing the API...\n**\n");

	pw = getpwuid(getuid());
	strlcpy(username, pw->pw_name, ଆକାର(username));

	/* gethostname(hostname, sizeof(hostname)); */

	printf("login_alloc_entry test (no host info):\n");

	/* FIXME fake tty more effectively - this could upset some platforms */
	li1 = login_alloc_entry((ପୂର୍ଣ୍ଣସଂଖ୍ୟା)getpid(), username, ଖାଲି, ttyname(0));
	strlcpy(li1->progname, "OpenSSH-logintest", ଆକାର(li1->progname));

	ଯଦି (be_verbose)
		dump_logininfo(li1, "li1");

	printf("Setting host address info for 'localhost' (may call out):\n");
	ଯଦି (! (he = gethostbyname("localhost"))) {
		printf("Couldn't set hostname(lookup failed)\n");
	} ଅନ୍ୟଥା {
		/* NOTE: this is messy, but typically a program wouldn't have to set
		 *  any of this, a sockaddr_in* would be already prepared */
		memcpy((ଶୂନ୍ୟ *)&(sa_in4.sin_addr), (ଶୂନ୍ୟ *)&(he->h_addr_list[0][0]),
		    ଆକାର(ସଂରଚନା in_addr));
		login_set_addr(li1, (ସଂରଚନା sockaddr *) &sa_in4, ଆକାର(sa_in4));
		strlcpy(li1->hostname, "localhost", ଆକାର(li1->hostname));
	}
	ଯଦି (be_verbose)
		dump_logininfo(li1, "li1");

	ଯଦି ((ପୂର୍ଣ୍ଣସଂଖ୍ୟା)geteuid() != 0) {
		printf("NOT RUNNING LOGIN TESTS - you are not root!\n");
		ଫେରନ୍ତୁ 1;
	}

	ଯଦି (nologtest)
		ଫେରନ୍ତୁ 1;

	ଧାଡ଼ି_stripname(stripline, li1->ଧାଡ଼ି, ଆକାର(stripline));

	printf("Performing an invalid login attempt (no type field)\n--\n");
	login_write(li1);
	printf("--\n(Should have written errors to stderr)\n");

#ifdef HAVE_TIME_H
	(ଶୂନ୍ୟ)time(&t0);
	strlcpy(s_t0, ctime(&t0), ଆକାର(s_t0));
	t1 = login_get_lastlog_time(getuid());
	strlcpy(s_t1, ctime(&t1), ଆକାର(s_t1));
	printf("Before logging in:\n\tcurrent time is %d - %s\t"
	    "lastlog time is %d - %s\n",
	    (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)t0, s_t0, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)t1, s_t1);
#endif

	printf("Performing a login on line %s ", stripline);
#ifdef HAVE_TIME_H
	(ଶୂନ୍ୟ)time(&logintime);
	strlcpy(s_logintime, ctime(&logintime), ଆକାର(s_logintime));
	printf("at %d - %s", (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)logintime, s_logintime);
#endif
	printf("--\n");
	login_login(li1);

	snprintf(cmdstring, ଆକାର(cmdstring), "who | grep '%s '",
		 stripline);
	system(cmdstring);

	printf("--\nPausing for %d second(s)...\n", PAUSE_BEFORE_LOGOUT);
	sleep(PAUSE_BEFORE_LOGOUT);

	printf("Performing a logout ");
#ifdef HAVE_TIME_H
	(ଶୂନ୍ୟ)time(&logouttime);
	strlcpy(s_logouttime, ctime(&logouttime), ଆକାର(s_logouttime));
	printf("at %d - %s", (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)logouttime, s_logouttime);
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
	strlcpy(s_t2, ctime(&t2), ଆକାର(s_t2));
	printf("After logging in, lastlog time is %d - %s\n", (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)t2, s_t2);
	ଯଦି (t1 == t2)
		printf("The lastlog times before and after logging in are the "
		    "same.\nThis indicates that lastlog is ** NOT WORKING "
		    "CORRECTLY **\n");
	ଅନ୍ୟଥା ଯଦି (t0 != t2)
		/* We can be off by a second or so, even when recording works fine.
		 * I'm not 100% sure why, but it's true. */
		printf("** The login time and the lastlog time differ.\n"
		    "** This indicates that lastlog is either recording the "
		    "wrong time,\n** or retrieving the wrong entry.\n"
		    "If it's off by less than %d second(s) "
		    "run the test again.\n", PAUSE_BEFORE_LOGOUT);
	ଅନ୍ୟଥା
		printf("lastlog agrees with the login time. This is a good thing.\n");

#endif

	printf("--\nThe output of 'last' shown next should have "
	    "an entry for root \n  on %s for the time shown above:\n--\n",
	    stripline);
	snprintf(cmdstring, ଆକାର(cmdstring), "last | grep '%s ' | head -3",
		 stripline);
	system(cmdstring);

	printf("--\nEnd of login test.\n");

	login_free_entry(li1);

	ଫେରନ୍ତୁ 1;
} /* testAPI() */


ଶୂନ୍ୟ
test_ଧାଡ଼ି_Name(ଅକ୍ଷର *ଧାଡ଼ି)
{
	/* have to null-terminate - these functions are designed for
	 * structures with fixed-length char arrays, and don't null-term.*/
	ଅକ୍ଷର full[17], strip[9], abbrev[5];

	memset(full, '\0', ଆକାର(full));
	memset(strip, '\0', ଆକାର(strip));
	memset(abbrev, '\0', ଆକାର(abbrev));

	ଧାଡ଼ି_fullname(full, ଧାଡ଼ି, ଆକାର(full)-1);
	ଧାଡ଼ି_stripname(strip, full, ଆକାର(strip)-1);
	ଧାଡ଼ି_abbrevname(abbrev, full, ଆକାର(abbrev)-1);
	printf("%s: %s, %s, %s\n", ଧାଡ଼ି, full, strip, abbrev);

} /* testLineName() */


ପୂର୍ଣ୍ଣସଂଖ୍ୟା
testOutput()
{
	printf("**\n** Testing linename functions\n**\n");
	test_ଧାଡ଼ି_Name("/dev/pts/1");
	test_ଧାଡ଼ି_Name("pts/1");
	test_ଧାଡ଼ି_Name("pts/999");
	test_ଧାଡ଼ି_Name("/dev/ttyp00");
	test_ଧାଡ଼ି_Name("ttyp00");

	ଫେରନ୍ତୁ 1;
} /* testOutput() */


/* show which options got compiled in */
ଶୂନ୍ୟ
showOptions(ଶୂନ୍ୟ)
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


ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର *argv[])
{
	printf("Platform-independent login recording test driver\n");

	__progname = ssh_get_progname(argv[0]);
	ଯଦି (argc == 2) {
		ଯଦି (strncmp(argv[1], "-i", 3) == 0)
			compile_opts_only = 1;
		ଅନ୍ୟଥା ଯଦି (strncmp(argv[1], "-v", 3) == 0)
			be_verbose=1;
	}

	ଯଦି (!compile_opts_only) {
		ଯଦି (be_verbose && !testOutput())
			ଫେରନ୍ତୁ 1;

		ଯଦି (!testAPI())
			ଫେରନ୍ତୁ 1;
	}

	showOptions();

	ଫେରନ୍ତୁ 0;
} /* main() */

