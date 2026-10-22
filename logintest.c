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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/wait.h>
#അന്തര്ഭാവ <sys/socket.h>

#അന്തര്ഭാവ <netinet/in.h>

#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <time.h>

#അന്തര്ഭാവ "loginrec.h"

ബാഹ്യ അക്ഷരം *__progname;

#define PAUSE_BEFORE_LOGOUT 3

പൂർണ്ണസംഖ്യ nologtest = 0;
പൂർണ്ണസംഖ്യ compile_opts_only = 0;
പൂർണ്ണസംഖ്യ be_verbose = 0;


/* Dump a logininfo to stdout. Assumes a tab size of 8 chars. */
ശൂന്യം
dump_logininfo(ഘടന logininfo *li, അക്ഷരം *descname)
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
	    li->pid, li->uid, li->വരി,
	    li->username, li->hostname, li->exit,
	    li->termination, li->tv_sec, li->tv_usec,
	    li->hostaddr.sa.sa_family);
}


പൂർണ്ണസംഖ്യ
testAPI()
{
	ഘടന logininfo *li1;
	ഘടന passwd *pw;
	ഘടന hostent *he;
	ഘടന sockaddr_in sa_in4;
	അക്ഷരം cmdstring[256], stripline[8];
	അക്ഷരം username[32];
#ifdef HAVE_TIME_H
	time_t t0, t1, t2, logintime, logouttime;
	അക്ഷരം s_t0[64],s_t1[64],s_t2[64];
	അക്ഷരം s_logintime[64], s_logouttime[64]; /* ctime() strings */
#endif

	printf("**\n** Testing the API...\n**\n");

	pw = getpwuid(getuid());
	strlcpy(username, pw->pw_name, വലുപ്പം(username));

	/* gethostname(hostname, sizeof(hostname)); */

	printf("login_alloc_entry test (no host info):\n");

	/* FIXME fake tty more effectively - this could upset some platforms */
	li1 = login_alloc_entry((പൂർണ്ണസംഖ്യ)getpid(), username, ശൂന്യ, ttyname(0));
	strlcpy(li1->progname, "OpenSSH-logintest", വലുപ്പം(li1->progname));

	എങ്കിൽ (be_verbose)
		dump_logininfo(li1, "li1");

	printf("Setting host address info for 'localhost' (may call out):\n");
	എങ്കിൽ (! (he = gethostbyname("localhost"))) {
		printf("Couldn't set hostname(lookup failed)\n");
	} അല്ലെങ്കിൽ {
		/* NOTE: this is messy, but typically a program wouldn't have to set
		 *  any of this, a sockaddr_in* would be already prepared */
		memcpy((ശൂന്യം *)&(sa_in4.sin_addr), (ശൂന്യം *)&(he->h_addr_list[0][0]),
		    വലുപ്പം(ഘടന in_addr));
		login_set_addr(li1, (ഘടന sockaddr *) &sa_in4, വലുപ്പം(sa_in4));
		strlcpy(li1->hostname, "localhost", വലുപ്പം(li1->hostname));
	}
	എങ്കിൽ (be_verbose)
		dump_logininfo(li1, "li1");

	എങ്കിൽ ((പൂർണ്ണസംഖ്യ)geteuid() != 0) {
		printf("NOT RUNNING LOGIN TESTS - you are not root!\n");
		തിരികെ 1;
	}

	എങ്കിൽ (nologtest)
		തിരികെ 1;

	വരി_stripname(stripline, li1->വരി, വലുപ്പം(stripline));

	printf("Performing an invalid login attempt (no type field)\n--\n");
	login_write(li1);
	printf("--\n(Should have written errors to stderr)\n");

#ifdef HAVE_TIME_H
	(ശൂന്യം)time(&t0);
	strlcpy(s_t0, ctime(&t0), വലുപ്പം(s_t0));
	t1 = login_get_lastlog_time(getuid());
	strlcpy(s_t1, ctime(&t1), വലുപ്പം(s_t1));
	printf("Before logging in:\n\tcurrent time is %d - %s\t"
	    "lastlog time is %d - %s\n",
	    (പൂർണ്ണസംഖ്യ)t0, s_t0, (പൂർണ്ണസംഖ്യ)t1, s_t1);
#endif

	printf("Performing a login on line %s ", stripline);
#ifdef HAVE_TIME_H
	(ശൂന്യം)time(&logintime);
	strlcpy(s_logintime, ctime(&logintime), വലുപ്പം(s_logintime));
	printf("at %d - %s", (പൂർണ്ണസംഖ്യ)logintime, s_logintime);
#endif
	printf("--\n");
	login_login(li1);

	snprintf(cmdstring, വലുപ്പം(cmdstring), "who | grep '%s '",
		 stripline);
	system(cmdstring);

	printf("--\nPausing for %d second(s)...\n", PAUSE_BEFORE_LOGOUT);
	sleep(PAUSE_BEFORE_LOGOUT);

	printf("Performing a logout ");
#ifdef HAVE_TIME_H
	(ശൂന്യം)time(&logouttime);
	strlcpy(s_logouttime, ctime(&logouttime), വലുപ്പം(s_logouttime));
	printf("at %d - %s", (പൂർണ്ണസംഖ്യ)logouttime, s_logouttime);
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
	strlcpy(s_t2, ctime(&t2), വലുപ്പം(s_t2));
	printf("After logging in, lastlog time is %d - %s\n", (പൂർണ്ണസംഖ്യ)t2, s_t2);
	എങ്കിൽ (t1 == t2)
		printf("The lastlog times before and after logging in are the "
		    "same.\nThis indicates that lastlog is ** NOT WORKING "
		    "CORRECTLY **\n");
	അല്ലെങ്കിൽ എങ്കിൽ (t0 != t2)
		/* We can be off by a second or so, even when recording works fine.
		 * I'm not 100% sure why, but it's true. */
		printf("** The login time and the lastlog time differ.\n"
		    "** This indicates that lastlog is either recording the "
		    "wrong time,\n** or retrieving the wrong entry.\n"
		    "If it's off by less than %d second(s) "
		    "run the test again.\n", PAUSE_BEFORE_LOGOUT);
	അല്ലെങ്കിൽ
		printf("lastlog agrees with the login time. This is a good thing.\n");

#endif

	printf("--\nThe output of 'last' shown next should have "
	    "an entry for root \n  on %s for the time shown above:\n--\n",
	    stripline);
	snprintf(cmdstring, വലുപ്പം(cmdstring), "last | grep '%s ' | head -3",
		 stripline);
	system(cmdstring);

	printf("--\nEnd of login test.\n");

	login_free_entry(li1);

	തിരികെ 1;
} /* testAPI() */


ശൂന്യം
test_വരി_Name(അക്ഷരം *വരി)
{
	/* have to null-terminate - these functions are designed for
	 * structures with fixed-length char arrays, and don't null-term.*/
	അക്ഷരം full[17], strip[9], abbrev[5];

	memset(full, '\0', വലുപ്പം(full));
	memset(strip, '\0', വലുപ്പം(strip));
	memset(abbrev, '\0', വലുപ്പം(abbrev));

	വരി_fullname(full, വരി, വലുപ്പം(full)-1);
	വരി_stripname(strip, full, വലുപ്പം(strip)-1);
	വരി_abbrevname(abbrev, full, വലുപ്പം(abbrev)-1);
	printf("%s: %s, %s, %s\n", വരി, full, strip, abbrev);

} /* testLineName() */


പൂർണ്ണസംഖ്യ
testOutput()
{
	printf("**\n** Testing linename functions\n**\n");
	test_വരി_Name("/dev/pts/1");
	test_വരി_Name("pts/1");
	test_വരി_Name("pts/999");
	test_വരി_Name("/dev/ttyp00");
	test_വരി_Name("ttyp00");

	തിരികെ 1;
} /* testOutput() */


/* show which options got compiled in */
ശൂന്യം
showOptions(ശൂന്യം)
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


പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം *argv[])
{
	printf("Platform-independent login recording test driver\n");

	__progname = ssh_get_progname(argv[0]);
	എങ്കിൽ (argc == 2) {
		എങ്കിൽ (strncmp(argv[1], "-i", 3) == 0)
			compile_opts_only = 1;
		അല്ലെങ്കിൽ എങ്കിൽ (strncmp(argv[1], "-v", 3) == 0)
			be_verbose=1;
	}

	എങ്കിൽ (!compile_opts_only) {
		എങ്കിൽ (be_verbose && !testOutput())
			തിരികെ 1;

		എങ്കിൽ (!testAPI())
			തിരികെ 1;
	}

	showOptions();

	തിരികെ 0;
} /* main() */

