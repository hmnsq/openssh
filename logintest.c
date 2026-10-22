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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/wait.h>
#अन्तर्भाव <sys/socket.h>

#अन्तर्भाव <netinet/in.h>

#अन्तर्भाव <unistd.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <time.h>

#अन्तर्भाव "loginrec.h"

बाह्य वर्ण *__progname;

#define PAUSE_BEFORE_LOGOUT 3

पूर्णाङ्क nologtest = 0;
पूर्णाङ्क compile_opts_only = 0;
पूर्णाङ्क be_verbose = 0;


/* Dump a logininfo to stdout. Assumes a tab size of 8 chars. */
शून्य
dump_logininfo(संरचना logininfo *li, वर्ण *descname)
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
	    li->pid, li->uid, li->ओळ,
	    li->username, li->hostname, li->exit,
	    li->termination, li->tv_sec, li->tv_usec,
	    li->hostaddr.sa.sa_family);
}


पूर्णाङ्क
testAPI()
{
	संरचना logininfo *li1;
	संरचना passwd *pw;
	संरचना hostent *he;
	संरचना sockaddr_in sa_in4;
	वर्ण cmdstring[256], stripline[8];
	वर्ण username[32];
#ifdef HAVE_TIME_H
	time_t t0, t1, t2, logintime, logouttime;
	वर्ण s_t0[64],s_t1[64],s_t2[64];
	वर्ण s_logintime[64], s_logouttime[64]; /* ctime() strings */
#endif

	printf("**\n** Testing the API...\n**\n");

	pw = getpwuid(getuid());
	strlcpy(username, pw->pw_name, परिमाण(username));

	/* gethostname(hostname, sizeof(hostname)); */

	printf("login_alloc_entry test (no host info):\n");

	/* FIXME fake tty more effectively - this could upset some platforms */
	li1 = login_alloc_entry((पूर्णाङ्क)getpid(), username, रिक्त, ttyname(0));
	strlcpy(li1->progname, "OpenSSH-logintest", परिमाण(li1->progname));

	यदि (be_verbose)
		dump_logininfo(li1, "li1");

	printf("Setting host address info for 'localhost' (may call out):\n");
	यदि (! (he = gethostbyname("localhost"))) {
		printf("Couldn't set hostname(lookup failed)\n");
	} अन्यथा {
		/* NOTE: this is messy, but typically a program wouldn't have to set
		 *  any of this, a sockaddr_in* would be already prepared */
		memcpy((शून्य *)&(sa_in4.sin_addr), (शून्य *)&(he->h_addr_list[0][0]),
		    परिमाण(संरचना in_addr));
		login_set_addr(li1, (संरचना sockaddr *) &sa_in4, परिमाण(sa_in4));
		strlcpy(li1->hostname, "localhost", परिमाण(li1->hostname));
	}
	यदि (be_verbose)
		dump_logininfo(li1, "li1");

	यदि ((पूर्णाङ्क)geteuid() != 0) {
		printf("NOT RUNNING LOGIN TESTS - you are not root!\n");
		प्रत्यागम 1;
	}

	यदि (nologtest)
		प्रत्यागम 1;

	ओळ_stripname(stripline, li1->ओळ, परिमाण(stripline));

	printf("Performing an invalid login attempt (no type field)\n--\n");
	login_write(li1);
	printf("--\n(Should have written errors to stderr)\n");

#ifdef HAVE_TIME_H
	(शून्य)time(&t0);
	strlcpy(s_t0, ctime(&t0), परिमाण(s_t0));
	t1 = login_get_lastlog_time(getuid());
	strlcpy(s_t1, ctime(&t1), परिमाण(s_t1));
	printf("Before logging in:\n\tcurrent time is %d - %s\t"
	    "lastlog time is %d - %s\n",
	    (पूर्णाङ्क)t0, s_t0, (पूर्णाङ्क)t1, s_t1);
#endif

	printf("Performing a login on line %s ", stripline);
#ifdef HAVE_TIME_H
	(शून्य)time(&logintime);
	strlcpy(s_logintime, ctime(&logintime), परिमाण(s_logintime));
	printf("at %d - %s", (पूर्णाङ्क)logintime, s_logintime);
#endif
	printf("--\n");
	login_login(li1);

	snprintf(cmdstring, परिमाण(cmdstring), "who | grep '%s '",
		 stripline);
	system(cmdstring);

	printf("--\nPausing for %d second(s)...\n", PAUSE_BEFORE_LOGOUT);
	sleep(PAUSE_BEFORE_LOGOUT);

	printf("Performing a logout ");
#ifdef HAVE_TIME_H
	(शून्य)time(&logouttime);
	strlcpy(s_logouttime, ctime(&logouttime), परिमाण(s_logouttime));
	printf("at %d - %s", (पूर्णाङ्क)logouttime, s_logouttime);
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
	strlcpy(s_t2, ctime(&t2), परिमाण(s_t2));
	printf("After logging in, lastlog time is %d - %s\n", (पूर्णाङ्क)t2, s_t2);
	यदि (t1 == t2)
		printf("The lastlog times before and after logging in are the "
		    "same.\nThis indicates that lastlog is ** NOT WORKING "
		    "CORRECTLY **\n");
	अन्यथा यदि (t0 != t2)
		/* We can be off by a second or so, even when recording works fine.
		 * I'm not 100% sure why, but it's true. */
		printf("** The login time and the lastlog time differ.\n"
		    "** This indicates that lastlog is either recording the "
		    "wrong time,\n** or retrieving the wrong entry.\n"
		    "If it's off by less than %d second(s) "
		    "run the test again.\n", PAUSE_BEFORE_LOGOUT);
	अन्यथा
		printf("lastlog agrees with the login time. This is a good thing.\n");

#endif

	printf("--\nThe output of 'last' shown next should have "
	    "an entry for root \n  on %s for the time shown above:\n--\n",
	    stripline);
	snprintf(cmdstring, परिमाण(cmdstring), "last | grep '%s ' | head -3",
		 stripline);
	system(cmdstring);

	printf("--\nEnd of login test.\n");

	login_free_entry(li1);

	प्रत्यागम 1;
} /* testAPI() */


शून्य
test_ओळ_Name(वर्ण *ओळ)
{
	/* have to null-terminate - these functions are designed for
	 * structures with fixed-length char arrays, and don't null-term.*/
	वर्ण full[17], strip[9], abbrev[5];

	memset(full, '\0', परिमाण(full));
	memset(strip, '\0', परिमाण(strip));
	memset(abbrev, '\0', परिमाण(abbrev));

	ओळ_fullname(full, ओळ, परिमाण(full)-1);
	ओळ_stripname(strip, full, परिमाण(strip)-1);
	ओळ_abbrevname(abbrev, full, परिमाण(abbrev)-1);
	printf("%s: %s, %s, %s\n", ओळ, full, strip, abbrev);

} /* testLineName() */


पूर्णाङ्क
testOutput()
{
	printf("**\n** Testing linename functions\n**\n");
	test_ओळ_Name("/dev/pts/1");
	test_ओळ_Name("pts/1");
	test_ओळ_Name("pts/999");
	test_ओळ_Name("/dev/ttyp00");
	test_ओळ_Name("ttyp00");

	प्रत्यागम 1;
} /* testOutput() */


/* show which options got compiled in */
शून्य
showOptions(शून्य)
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


पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण *argv[])
{
	printf("Platform-independent login recording test driver\n");

	__progname = ssh_get_progname(argv[0]);
	यदि (argc == 2) {
		यदि (strncmp(argv[1], "-i", 3) == 0)
			compile_opts_only = 1;
		अन्यथा यदि (strncmp(argv[1], "-v", 3) == 0)
			be_verbose=1;
	}

	यदि (!compile_opts_only) {
		यदि (be_verbose && !testOutput())
			प्रत्यागम 1;

		यदि (!testAPI())
			प्रत्यागम 1;
	}

	showOptions();

	प्रत्यागम 0;
} /* main() */

